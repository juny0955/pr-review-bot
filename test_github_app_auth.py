import base64
import datetime
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from github_app_auth import InstallationAuth


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = Path(self.tmp.name, 'test-key.pem')
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(self.key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        self.key.chmod(0o600)
        self.now = 1700000000
        self.response = {'token': 'test-secret-token', 'expires_at': '2023-11-14T22:43:20Z',
                         'permissions': {'pull_requests': 'read'},
                         'repositories': [{'id': 12, 'full_name': 'owner/repo'}]}
        self.api = Mock(return_value=self.response)
        self.auth = InstallationAuth(123, 456, self.key, {12: 'owner/repo'}, 'read', self.api, clock=lambda: self.now)

    def test_rejects_2041_bit_key_despite_256_byte_signature(self):
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2041', '-out', str(self.key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        modulus = subprocess.check_output(['openssl', 'rsa', '-noout', '-modulus', '-in', str(self.key)], timeout=10)
        self.assertEqual(int(modulus.strip().split(b'=')[1], 16).bit_length(), 2041)
        signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(self.key)], input=b'test', timeout=10)
        self.assertEqual(len(signature), 256)
        with self.assertRaisesRegex(RuntimeError, '^authentication failed$'):
            self.auth.token(12, 'owner/repo')
        self.api.assert_not_called()

    def test_modulus_boundaries_and_malformed_output(self):
        real_run = subprocess.run
        for bits in (2047, 2048, 8192, 8193):
            value = format(1 << (bits - 1), 'X').encode()
            with self.subTest(bits=bits):
                self.api.reset_mock()
                def run(args, **kwargs):
                    if '-modulus' in args:
                        return subprocess.CompletedProcess(args, 0, b'Modulus=' + value + b'\n')
                    return real_run(args, **kwargs)
                with patch('github_app_auth.subprocess.run', side_effect=run):
                    if 2048 <= bits <= 8192:
                        self.auth.token(12, 'owner/repo')
                        self.api.assert_called_once()
                    else:
                        with self.assertRaisesRegex(RuntimeError, '^authentication failed$'):
                            self.auth.token(12, 'owner/repo')
                        self.api.assert_not_called()
        for value in (b'', b'Modulus=xyz\n', b'Modulus=1\nextra\n'):
            self.api.reset_mock()
            def run(args, **kwargs):
                if '-modulus' in args:
                    return subprocess.CompletedProcess(args, 0, value)
                return real_run(args, **kwargs)
            with self.subTest(value=value), patch('github_app_auth.subprocess.run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, '^authentication failed$'):
                    self.auth.token(12, 'owner/repo')
                self.api.assert_not_called()

    def test_expired_jwt_is_not_sent(self):
        self.auth.clock = Mock(side_effect=[self.now, self.now + 540])
        with self.assertRaisesRegex(RuntimeError, '^authentication failed$'):
            self.auth.token(12, 'owner/repo')
        self.api.assert_not_called()

    def test_signed_jwt_scope_and_expiry(self):
        token, expiry = self.auth.token(12, 'owner/repo')
        self.assertEqual((token, expiry), ('test-secret-token', 1700001800))
        jwt, installation, body = self.api.call_args.args
        head, payload, signature = jwt.split('.')
        decode = lambda x: base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
        self.assertEqual(json.loads(decode(head)), {'alg': 'RS256', 'typ': 'JWT'})
        self.assertEqual(json.loads(decode(payload)), {'iat': self.now - 60, 'exp': self.now + 540, 'iss': '123'})
        self.assertEqual(installation, 456)
        self.assertEqual(body, {'repository_ids': [12], 'permissions': {'pull_requests': 'read'}})
        public = subprocess.check_output(['openssl', 'pkey', '-in', str(self.key), '-pubout'], stderr=subprocess.DEVNULL, timeout=10)
        pub = Path(self.tmp.name, 'public.pem'); pub.write_bytes(public)
        sig = Path(self.tmp.name, 'sig'); sig.write_bytes(decode(signature))
        subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(pub), '-signature', str(sig)], input=(head + '.' + payload).encode(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)

    def test_policy_and_sensitive_errors(self):
        with self.assertRaises(ValueError): self.auth.token(13, 'owner/repo')
        self.api.assert_not_called()
        self.key.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'authentication failed') as err: self.auth.token(12, 'owner/repo')
        self.assertNotIn(str(self.key), repr(err.exception))
        self.api.assert_not_called()
        self.key.chmod(0o600)
        self.api.side_effect = RuntimeError('401 test-secret-token')
        with self.assertRaisesRegex(RuntimeError, 'authentication failed') as err: self.auth.token(12, 'owner/repo')
        self.assertIsNone(err.exception.__cause__)
        self.assertNotIn('test-secret-token', str(err.exception))

    def test_rejects_expired_or_overprivileged_response(self):
        for change in ({'expires_at': '2023-11-14T22:13:20Z'},
                       {'permissions': {'pull_requests': 'write'}},
                       {'permissions': {'pull_requests': 'read', 'contents': 'write'}},
                       {'repositories': [{'id': 99, 'full_name': 'owner/repo'}]},
                       {'token': ''}):
            with self.subTest(change=change):
                self.api.return_value = dict(self.response, **change)
                with self.assertRaisesRegex(RuntimeError, 'authentication failed'): self.auth.token(12, 'owner/repo')

    def test_signing_timeout_is_sanitized(self):
        with patch('github_app_auth.subprocess.run', side_effect=subprocess.TimeoutExpired('secret', 10)) as run:
            with self.assertRaisesRegex(RuntimeError, '^authentication failed$') as error:
                self.auth.token(12, 'owner/repo')
            self.assertIsNone(error.exception.__context__)
            self.assertEqual(run.call_args.kwargs['timeout'], 10)
            self.assertFalse(run.call_args.kwargs['shell'])
            self.api.assert_not_called()

    def test_write_scope_is_explicit_and_symlinks_rejected(self):
        auth = InstallationAuth(123, 456, self.key, {12: 'owner/repo'}, 'publish', self.api, clock=lambda: self.now)
        self.response['permissions'] = {'pull_requests': 'write'}
        auth.token(12, 'owner/repo')
        self.assertEqual(self.api.call_args.args[2]['permissions'], {'pull_requests': 'write'})
        link = Path(self.tmp.name, 'link'); link.symlink_to(self.key)
        auth = InstallationAuth(123, 456, link, {12: 'owner/repo'}, 'read', self.api, clock=lambda: self.now)
        with self.assertRaises(RuntimeError): auth.token(12, 'owner/repo')


if __name__ == '__main__':
    unittest.main()
