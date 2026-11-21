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
        repo_name = obj['base']['repo']['full_name']
        if type(repo_id) is not int or repo_name != repo or allowed(self.repos).get(repo_id) != repo:
            raise ValueError('GitHub repository identity mismatch')
        state, draft, sha = obj['state'], obj['draft'], obj['head']['sha']
        base_sha = obj['base']['sha']
        if (state not in ('open', 'closed') or type(draft) is not bool
                or not isinstance(sha, str) or not SHA.fullmatch(sha)
                or not isinstance(base_sha, str) or not SHA.fullmatch(base_sha)):
            raise ValueError('invalid GitHub PR response')
        return {'state': state, 'draft': draft, 'sha': sha, 'base_sha': base_sha,
                'repo_id': repo_id, 'repo': repo_name}

    def diff(self, repo, number, sha, base_sha):
        endpoint = _endpoint(repo, number, self.repos)
        if (not isinstance(sha, str) or not SHA.fullmatch(sha)
                or not isinstance(base_sha, str) or not SHA.fullmatch(base_sha)):
            raise ValueError('invalid SHA')
        expected = self.current(repo, number)
        if (expected.get('state') != 'open' or expected.get('draft') is not False
                or expected.get('sha') != sha or expected.get('base_sha') != base_sha):
            raise ValueError('stale or ineligible pull request')
        # The PR diff endpoint is mutable and pre/post checks cannot exclude ABA.
        # A compare of current base/head is not necessarily the PR's historical
        # merge-base diff. Do not review until a pinned equivalent is available.
        raise RuntimeError('immutable pull request diff unavailable')
