"""Explicitly invoked, read-only GitHub adapter and offline request serializer."""
import json
import os
import selectors
import subprocess
import time
import tempfile
import sys
import signal
import ctypes
import stat
from contextlib import ExitStack

from worker import MAX_DIFF, SHA
from repo_config import allowed
from github_app_transport import read_transport

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


MAX_GIT_FILE = 64 * 1024 * 1024
GIT_TIMEOUT = 60
MAX_GIT_STORAGE = 256 * 1024 * 1024


def _bounded_git_root():
    """Validate the one administrator-provisioned scratch mount, or fail closed."""
    path = '/run/pr-review-bot-diff'
    if os.environ.get('PR_DIFF_TMPDIR') != path:
        raise RuntimeError('bounded git scratch unavailable: invalid path')
    try:
        for parent in ('/', '/run'):
            info = os.lstat(parent)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('untrusted parent')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            visible = os.lstat(path)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or (info.st_dev, info.st_ino) != (visible.st_dev, visible.st_ino)
                    or not os.path.ismount(path)):
                raise ValueError('untrusted mount')
            buf = ctypes.create_string_buffer(256)
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.fstatfs(fd, ctypes.byref(buf)) != 0:
                raise OSError(ctypes.get_errno(), 'fstatfs failed')
            size = os.fstatvfs(fd)
            if ctypes.c_long.from_buffer(buf).value != 0x01021994 or not 0 < size.f_blocks * size.f_frsize <= MAX_GIT_STORAGE:
                raise ValueError('unbounded or non-tmpfs mount')
        finally:
            os.close(fd)
    except (OSError, ValueError, AttributeError) as exc:
        raise RuntimeError('bounded git scratch unavailable') from exc
    return path


def _pinned_diff(remote, number, sha, base_sha):
    """Fetch into an isolated bare repository and diff immutable commit objects."""
    deadline = time.monotonic() + GIT_TIMEOUT
    with ExitStack() as stack:
        root = _bounded_git_root()
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, root_fd)
        directory = stack.enter_context(tempfile.TemporaryDirectory(prefix='pr-diff-', dir=root))
        opened, visible = os.fstat(root_fd), os.lstat(root)
        if (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino):
            raise RuntimeError('bounded git scratch changed')
        env = {'PATH': os.defpath, 'HOME': directory, 'XDG_CONFIG_HOME': directory,
               'TMPDIR': directory,
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
               'GIT_ATTR_NOSYSTEM': '1', 'LC_ALL': 'C',
               'GH_CONFIG_DIR': os.path.expanduser('~/.config/gh')}
        for name in ('GH_TOKEN', 'GITHUB_TOKEN'):
            if name in os.environ:
                env[name] = os.environ[name]
        def run(args, limit=4096):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('git timed out')
            with tempfile.TemporaryFile(dir=directory) as output:
                cmd = ['git', '-c', 'core.hooksPath=/dev/null',
                       '-c', 'protocol.ext.allow=never', '-c', 'diff.external=',
                       '-c', 'credential.helper=',
                       '-c', 'credential.helper=!gh auth git-credential', *args]
                proc = subprocess.Popen([sys.executable, '-I', os.path.join(os.path.dirname(__file__),
                                         'git_limited_exec.py'), str(MAX_GIT_FILE), str(GIT_TIMEOUT), *cmd],
                                        cwd=directory, env=env, stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=subprocess.DEVNULL, start_new_session=True)
                try:
                    proc.wait(timeout=remaining)
                except BaseException as exc:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    finally:
                        proc.wait()
                    if isinstance(exc, subprocess.TimeoutExpired):
                        raise TimeoutError('git timed out') from exc
                    raise
                if proc.returncode:
                    raise RuntimeError('git command failed')
                if output.tell() > limit:
                    raise ValueError('git output too large')
                output.seek(0)
                return output.read()
        run(['init', '--bare', '-q', 'repo.git'])
        gitdir = '--git-dir=' + os.path.join(directory, 'repo.git')
        run([gitdir, 'fetch', '--no-tags', '--no-write-fetch-head', '--no-recurse-submodules',
             remote, f'+refs/pull/{number}/head:refs/pr/head', base_sha])
        actual = run([gitdir, 'rev-parse', '--verify', 'refs/pr/head^{commit}']).decode().strip()
        if actual != sha:
            raise ValueError('pull request head changed')
        run([gitdir, 'cat-file', '-e', base_sha + '^{commit}'])
        bases = run([gitdir, 'merge-base', '--all', base_sha, sha]).decode().splitlines()
        if len(bases) != 1 or not SHA.fullmatch(bases[0]):
            raise ValueError('expected exactly one merge base')
        return run([gitdir, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                    '--no-color', bases[0], sha, '--'], MAX_DIFF).decode('utf-8', 'strict')


def _endpoint(repo, number, repos):
    if repo not in allowed(repos).values() or type(number) is not int or number <= 0:
        raise ValueError('repository or pull request not allowed')
    return f'repos/{repo}/pulls/{number}'


class GitHubReadOnly:
    def __init__(self, repos, *, auth=None):
        allowed(repos)
        if auth is not None and getattr(auth, 'permission', None) != 'read':
            raise ValueError('read authentication required')
        self.repos = repos
        self.auth = auth

    def current(self, repo, number):
        endpoint = _endpoint(repo, number, self.repos)
        if self.auth is None:
            obj = json.loads(_gh_get(endpoint, 'application/vnd.github+json', MAX_METADATA))
        else:
            repo_id = next(ident for ident, name in allowed(self.repos).items() if name == repo)
            token, _ = self.auth.token(repo_id, repo)
            obj = read_transport(token, '/' + endpoint)
        if type(obj.get('number')) is not int or obj['number'] != number:
            raise ValueError('GitHub pull request identity mismatch')
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
        if self.auth is not None:
            # ponytail: fail closed until git fetch has isolated read-only credentials.
            raise RuntimeError('App-authenticated diff unavailable')
        if (not isinstance(sha, str) or not SHA.fullmatch(sha)
                or not isinstance(base_sha, str) or not SHA.fullmatch(base_sha)):
            raise ValueError('invalid SHA')
        expected = self.current(repo, number)
        if (expected.get('state') != 'open' or expected.get('draft') is not False
                or expected.get('sha') != sha or expected.get('base_sha') != base_sha):
            raise ValueError('stale or ineligible pull request')
        return _pinned_diff('https://github.com/' + repo + '.git', number, sha, base_sha)
