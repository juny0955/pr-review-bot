"""Explicitly invoked, read-only GitHub adapter and offline request serializer."""
import json
import os
import selectors
import subprocess
import time

from worker import MAX_DIFF, SHA
from repo_config import allowed

MAX_METADATA = 256 * 1024
TIMEOUT = 30


def _gh_get(endpoint, accept, limit):
    """Read at most limit bytes, terminating gh on overflow or timeout."""
    command = ['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
               '-H', 'Accept: ' + accept, endpoint]
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + TIMEOUT
    data = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError('GitHub request timed out')
                chunk = os.read(proc.stdout.fileno(), min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ValueError('GitHub response too large')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('GitHub request timed out')
        if proc.wait(timeout=remaining) != 0:
            raise RuntimeError('GitHub request failed')
        return bytes(data)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()


def _endpoint(repo, number, repos):
    if repo not in allowed(repos).values() or type(number) is not int or number <= 0:
        raise ValueError('repository or pull request not allowed')
    return f'repos/{repo}/pulls/{number}'


class GitHubReadOnly:
    def __init__(self, repos):
        allowed(repos)
        self.repos = repos

    def current(self, repo, number):
        endpoint = _endpoint(repo, number, self.repos)
        obj = json.loads(_gh_get(endpoint, 'application/vnd.github+json', MAX_METADATA))
        repo_id = obj['base']['repo']['id']
        if type(repo_id) is not int or allowed(self.repos).get(repo_id) != repo:
            raise ValueError('GitHub repository identity mismatch')
        state, draft, sha = obj['state'], obj['draft'], obj['head']['sha']
        if state not in ('open', 'closed') or type(draft) is not bool or not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise ValueError('invalid GitHub PR response')
        return {'state': state, 'draft': draft, 'sha': sha}

    def diff(self, repo, number, sha):
        endpoint = _endpoint(repo, number, self.repos)
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise ValueError('invalid SHA')
        expected = {'state': 'open', 'draft': False, 'sha': sha}
        if self.current(repo, number) != expected:
            raise ValueError('stale or ineligible pull request')
        data = _gh_get(endpoint, 'application/vnd.github.v3.diff', MAX_DIFF)
        if self.current(repo, number) != expected:
            raise ValueError('stale or ineligible pull request')
        return data.decode('utf-8')
