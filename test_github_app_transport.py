import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from github_app_transport import installation_transport, read_transport, MAX_RESPONSE, MAX_REQUEST, _https
from github_adapter import GitHubReadOnly
from github_app_auth import InstallationAuth


class TransportTests(unittest.TestCase):
    def connection(self, status=201, data=b'{}'):
        response = Mock(status=status)
        response.read.return_value = data
        conn = Mock()
        conn.getresponse.return_value = response
        return conn

    def test_installation_request_fixed_host_scope_and_headers(self):
        conn = self.connection(data=b'{"token":"fake"}')
        with patch('github_app_transport.http.client.HTTPSConnection', return_value=conn) as factory:
            result = _https('POST', '/app/installations/42/access_tokens', 'fake.jwt.signature', '{"repository_ids":[12]}')
        self.assertEqual(json.loads(result), {'token': 'fake'})
        factory.assert_called_once_with('api.github.com', timeout=15)
        args, kwargs = conn.request.call_args
        self.assertEqual(args[:2], ('POST', '/app/installations/42/access_tokens'))
        self.assertEqual(json.loads(kwargs['body']), {'repository_ids': [12]})
        self.assertEqual(kwargs['headers']['Authorization'], 'Bearer fake.jwt.signature')
        conn.close.assert_called_once()

    def test_failure_is_sanitized_and_redirect_never_followed(self):
        for status, data in [(302, b'secret'), (401, b'secret'), (201, b'x' * (MAX_RESPONSE + 1)), (201, b'not json')]:
            conn = self.connection(status, data)
            with self.subTest(status=status, size=len(data)), patch('github_app_transport.http.client.HTTPSConnection', return_value=conn) as factory:
                with self.assertRaises(Exception):
                    _https('POST', '/app/installations/1/access_tokens', 'secret', '{}')
                factory.assert_called_once()
                conn.close.assert_called_once()

    def test_invalid_inputs_do_not_connect(self):
        with patch('github_app_transport.subprocess.Popen') as factory:
            for jwt, ident, body in [('x\r\ny', 1, {}), ('x', True, {}), ('x', 1, {'x': 'a' * MAX_REQUEST})]:
                with self.assertRaises(RuntimeError):
                    installation_transport(jwt, ident, body)
            for path in ('https://evil.test/x', '//evil.test/x', '/repos/x/../y', '/repos/x/y?secret=x'):
                with self.assertRaises(RuntimeError):
                    read_transport('secret', path)
            factory.assert_not_called()

    def test_exception_and_timeout_are_sanitized(self):
        real = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            child = real([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
            children.append(child)
            return child
        with patch('github_app_transport.subprocess.Popen', side_effect=launch), patch('github_app_transport.TIMEOUT', 0.2):
            start = time.monotonic()
            with self.assertRaises(RuntimeError) as error:
                installation_transport('secret-jwt', 1, {})
            self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(str(error.exception), 'GitHub transport failed')
        self.assertIsNone(error.exception.__context__)
        self.assertIsNotNone(children[0].returncode)

    def test_auth_with_test_key_and_mock_https_pins_repository_and_scope(self):
        response = {'token': 'test-token', 'expires_at': '2023-11-14T22:43:20Z',
                    'permissions': {'pull_requests': 'read'},
                    'repositories': [{'id': 12, 'full_name': 'owner/repo'}]}
        original = subprocess.Popen
        def selective(args, **kwargs):
            if '-I' not in args:
                return original(args, **kwargs)
            script = 'import sys; sys.stdin.buffer.read(); sys.stdout.write(' + repr(json.dumps(response)) + ')'
            return original([sys.executable, '-c', script], **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'test.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            key.chmod(0o600)
            auth = InstallationAuth(1, 2, key, {12: 'owner/repo'}, 'read', installation_transport, clock=lambda: 1700000000)
            with patch('github_app_transport.subprocess.Popen', side_effect=selective):
                self.assertEqual(auth.token(12, 'owner/repo')[0], 'test-token')
                response['repositories'][0]['id'] = 13
                with self.assertRaisesRegex(RuntimeError, '^authentication failed$'):
                    auth.token(12, 'owner/repo')

    def test_actual_fifteen_second_deadline(self):
        original = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            child = original([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
            children.append(child)
            return child
        with patch('github_app_transport.subprocess.Popen', side_effect=launch):
            started = time.monotonic()
            with self.assertRaises(RuntimeError):
                installation_transport('fake-secret', 1, {})
            self.assertTrue(14.5 <= time.monotonic() - started < 18)
        self.assertEqual(children[0].returncode, -9)

    def test_child_decodes_pipe_and_writes_response(self):
        import io
        from github_app_transport import _child
        request = {'method': 'GET', 'path': '/repos/o/r/pulls/1', 'credential': 'fake-secret', 'body': None}
        stdin, stdout = Mock(), Mock()
        stdin.buffer = io.BytesIO(json.dumps(request).encode())
        stdout.buffer = io.BytesIO()
        with patch('github_app_transport.sys.stdin', stdin), patch('github_app_transport.sys.stdout', stdout), \
             patch('github_app_transport._https', return_value=b'{"ok":true}') as https:
            self.assertEqual(_child(), 0)
        https.assert_called_once_with('GET', '/repos/o/r/pulls/1', 'fake-secret', None)
        self.assertEqual(stdout.buffer.getvalue(), b'{"ok":true}')

    def test_read_mode_uses_only_explicit_read_auth_and_blocks_git_fallback(self):
        auth = Mock(permission='read')
        auth.token.return_value = ('read-secret', 1)
        pr = {'state': 'open', 'draft': False, 'head': {'sha': 'a' * 40}, 'base': {'sha': 'b' * 40, 'repo': {'id': 12, 'full_name': 'owner/repo'}}}
        with patch('github_adapter.read_transport', return_value=pr) as get, patch('github_adapter._gh_get') as gh, patch('github_adapter._pinned_diff') as git:
            adapter = GitHubReadOnly({12: 'owner/repo'}, auth=auth)
            self.assertEqual(adapter.current('owner/repo', 1)['repo_id'], 12)
            get.assert_called_once_with('read-secret', '/repos/owner/repo/pulls/1')
            with self.assertRaises(RuntimeError):
                adapter.diff('owner/repo', 1, 'a' * 40, 'b' * 40)
            gh.assert_not_called(); git.assert_not_called()
        with self.assertRaises(ValueError):
            GitHubReadOnly({12: 'owner/repo'}, auth=Mock(permission='write'))


if __name__ == '__main__':
    unittest.main()
