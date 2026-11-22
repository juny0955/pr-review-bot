"""Administrator-owned publication policy and approval store (local POSIX filesystems only)."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import time

from repo_config import allowed


def _trusted_directory(path):
    if not isinstance(path, (str, os.PathLike)) or not os.path.isabs(path):
        raise ValueError('no shared revocation gate')
    parts = Path(path).parts
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:]:
            if part in ('.', '..'):
                raise ValueError('unsafe gate path')
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                raise ValueError('unsafe gate path permissions')
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('gate directory must be private and owned by administrator')
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def locked_gate(path, timeout=5):
    directory = _trusted_directory(path)
    lock = None
    try:
        lock = os.open('lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ValueError('unsafe gate lock')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('revocation gate lock timeout')
                time.sleep(0.01)
        yield directory
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def _read_state(directory, name='state.json'):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError('unsafe gate state')
        state = json.load(stream)
    if (not isinstance(state, dict) or set(state) not in ({'policy', 'approvals', 'revision'}, {'policy', 'approvals', 'revision', 'auto_repos'})
            or not isinstance(state['policy'], dict) or not isinstance(state['approvals'], list)
            or not isinstance(state['revision'], str) or not re.fullmatch('[0-9a-f]{32}', state['revision'])):
        raise ValueError('invalid gate evidence')
    policy = {}
    for key, value in state['policy'].items():
        if not isinstance(key, str) or not key.isascii() or not key.isdigit() or str(int(key)) != key:
            raise ValueError('invalid gate policy')
        policy[int(key)] = value
    allowed(policy)
    auto = state.get('auto_repos', {})
    if (not isinstance(auto, dict) or any(
            key not in state['policy'] or state['policy'][key] != value
            or {'1466550689': 'juny0955/pr-review-bot',
                '1447840098': 'juny0955/rfsync'}.get(key) != value for key, value in auto.items())):
        raise ValueError('invalid automatic publication policy')
    for entry in state['approvals']:
        if (not isinstance(entry, list) or len(entry) != 6
                or type(entry[0]) is not int or entry[0] <= 0
                or not isinstance(entry[1], str) or allowed({entry[0]: entry[1]}).get(entry[0]) != entry[1]
                or type(entry[2]) is not int or entry[2] <= 0
                or any(not isinstance(x, str) or not re.fullmatch('[0-9a-f]{40}', x) for x in entry[3:5])
                or not isinstance(entry[5], str) or not re.fullmatch('[0-9a-f]{64}', entry[5])):
            raise ValueError('invalid gate approval')
    return state


def _version(state):
    return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def gate_snapshot(path):
    with locked_gate(path) as directory:
        state = _read_state(directory)
        return state, _version(state)


def update_gate(path, policy, approvals, *, expected=None, auto_repos=None):
    """CAS-replace state; omitted auto_repos disables automatic publication."""
    # Validate exactly as readers do, before replacing the authoritative state.
    import secrets
    with locked_gate(path) as directory:
        try:
            old = _read_state(directory)
        except FileNotFoundError:
            old = None
        if (old is None and expected is not None) or (old is not None and expected != _version(old)):
            raise ValueError('gate state conflict')
        name = '.state-' + secrets.token_hex(16)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump({'policy': policy, 'approvals': approvals, 'auto_repos': {} if auto_repos is None else auto_repos, 'revision': secrets.token_hex(16)}, stream, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            _read_state(directory, name)
            os.replace(name, 'state.json', src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass


@contextmanager
def authorize(path, identity, *, single_vps_mvp=False):
    with locked_gate(path) as directory:
        state = _read_state(directory)
        auto = single_vps_mvp is True and state.get('auto_repos', {}).get(str(identity[0])) == identity[1]
        if state['policy'].get(str(identity[0])) != identity[1] or (identity not in state['approvals'] and not auto):
            raise ValueError('publication not approved by shared revocation gate')
        yield
