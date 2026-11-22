"""Offline-by-default GitHub App installation-token acquisition.

The caller supplies a trusted transport; this module performs no HTTP itself.
"""
import base64
import datetime
import json
import math
import os
import re
import stat
import subprocess
import time

from repo_config import allowed


def _part(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


class InstallationAuth:
    def __init__(self, app_id, installation_id, key_path, repos, purpose, transport, *, clock=time.time):
        if (type(app_id) is not int or not 0 < app_id < 2**63
                or type(installation_id) is not int or not 0 < installation_id < 2**63
                or purpose not in ('read', 'publish') or not callable(transport) or not callable(clock)):
            raise ValueError('invalid authentication configuration')
        self.app_id, self.installation_id = app_id, installation_id
        allowed(repos)
        self.key_path, self.repos = os.fspath(key_path), repos
        self.permission = 'read' if purpose == 'read' else 'write'
        self.transport, self.clock = transport, clock

    def token(self, repo_id, repo):
        if type(repo_id) is not int or not isinstance(repo, str) or allowed(self.repos).get(repo_id) != repo:
            raise ValueError('repository not allowed')
        # Do not chain provider, subprocess, filesystem or parsing exceptions: they can contain secrets.
        try:
            return self._token(repo_id, repo)
        except Exception:
            pass
        raise RuntimeError('authentication failed') from None

    def _token(self, repo_id, repo):
        fd = os.open(self.key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or not 0 < info.st_size <= 16384):
                raise ValueError('unsafe key')
            subprocess.run(['openssl', 'rsa', '-check', '-noout', '-in', f'/proc/self/fd/{fd}'],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           pass_fds=(fd,), timeout=10, check=True, shell=False,
                           env={'PATH': os.defpath, 'LC_ALL': 'C'})
            modulus = subprocess.run(['openssl', 'rsa', '-noout', '-modulus', '-in', f'/proc/self/fd/{fd}'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     pass_fds=(fd,), timeout=10, check=True, shell=False,
                                     env={'PATH': os.defpath, 'LC_ALL': 'C'}).stdout
            if not re.fullmatch(rb'Modulus=[0-9A-Fa-f]{1,2048}\n', modulus):
                raise ValueError('invalid modulus')
            if not 2048 <= int(modulus[8:-1], 16).bit_length() <= 8192:
                raise ValueError('invalid modulus length')
            now = self.clock()
            if type(now) not in (int, float) or not math.isfinite(now) or not 0 < now < 253402300000:
                raise ValueError('invalid clock')
            now = int(now)
            header = _part(json.dumps({'alg': 'RS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
            payload = _part(json.dumps({'iat': now - 60, 'exp': now + 540, 'iss': str(self.app_id)}, separators=(',', ':')).encode())
            message = (header + '.' + payload).encode('ascii')
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', f'/proc/self/fd/{fd}'],
                                    input=message, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    pass_fds=(fd,), timeout=10, check=True, shell=False,
                                    env={'PATH': os.defpath, 'LC_ALL': 'C'})
        finally:
            os.close(fd)
        if not 256 <= len(result.stdout) <= 1024:
            raise ValueError('invalid signature')
        jwt = message.decode('ascii') + '.' + _part(result.stdout)
        current = self.clock()
        if (type(current) not in (int, float) or not math.isfinite(current)
                or not now - 60 <= current < now + 540):
            raise ValueError('expired JWT or invalid clock')
        permissions = {'pull_requests': self.permission}
        if allowed(self.repos).get(repo_id) != repo:
            raise ValueError('repository not allowed')
        response = self.transport(jwt, self.installation_id,
                                  {'repository_ids': [repo_id], 'permissions': permissions.copy()})
        if not isinstance(response, dict):
            raise ValueError('invalid response')
        token, expires = response.get('token'), response.get('expires_at')
        if (not isinstance(token, str) or not re.fullmatch(r'[\x21-\x7e]{1,4096}', token)
                or not isinstance(expires, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', expires)):
            raise ValueError('invalid response')
        expiry = datetime.datetime.strptime(expires, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
        current = self.clock()
        if (type(current) not in (int, float) or not math.isfinite(current)
                or not current + 60 < expiry <= current + 3600):
            raise ValueError('invalid expiry')
        actual = response.get('permissions')
        if not isinstance(actual, dict) or actual.get('pull_requests') != self.permission:
            raise ValueError('invalid permissions')
        if any(k not in ('pull_requests', 'metadata') or (k == 'metadata' and v != 'read') for k, v in actual.items()):
            raise ValueError('excess permissions')
        repositories = response.get('repositories')
        if (not isinstance(repositories, list) or len(repositories) != 1
                or not isinstance(repositories[0], dict) or type(repositories[0].get('id')) is not int
                or repositories[0].get('id') != repo_id or repositories[0].get('full_name') != repo):
            raise ValueError('invalid repository scope')
        return token, int(expiry)
