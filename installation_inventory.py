"""Validate installation inventories and reconcile local policy under the gate."""
from repo_config import allowed
import json
import os
import secrets
import stat
import tempfile
import time
from pathlib import Path


# ponytail: reject inventories above 100,000 rather than risk unbounded work.
MAX_REPOSITORIES = 100_000
PAGE_SIZE = 100


class SyncSuperseded(ValueError):
    pass


def _snapshot(fetch):
    repositories = {}
    names = set()
    expected = None
    page = 1
    while True:
        response = fetch(page, PAGE_SIZE)
        if not isinstance(response, dict):
            raise ValueError('invalid inventory page')
        total, entries = response.get('total_count'), response.get('repositories')
        if (type(total) is not int or not 0 <= total <= MAX_REPOSITORIES
                or not isinstance(entries, list)
                or (expected is not None and total != expected)):
            raise ValueError('invalid inventory page')
        expected = total
        remaining = total - (page - 1) * PAGE_SIZE
        if len(entries) != min(PAGE_SIZE, remaining):
            raise ValueError('incomplete inventory page')
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError('invalid repository')
            ident, name, private = entry.get('id'), entry.get('full_name'), entry.get('private')
            if type(ident) is not int or not isinstance(name, str) or type(private) is not bool:
                raise ValueError('invalid repository')
            allowed({ident: name})
            if ident in repositories or name.casefold() in names:
                raise ValueError('duplicate repository')
            repositories[ident] = (name, private)
            names.add(name.casefold())
        if len(repositories) == total:
            return repositories
        page += 1


def installation_snapshot(transport, token):
    """Read the entire installation through an injected GET transport.

    The token must already cover the whole installation, not one repository.
    This function does not acquire credentials or update authorization policy.
    """
    if not callable(transport) or not isinstance(token, str) or not token:
        raise ValueError('invalid inventory transport or token')
    return public_snapshot(lambda page, size: transport(
        token, f'/installation/repositories?per_page={size}&page={page}'))


def public_snapshot(fetch):
    """Return public ID/name mapping only after two identical complete reads.

    GitHub pagination is not a transactional snapshot. Two identical reads
    detect many concurrent changes but do not establish atomic consistency;
    callers must additionally coordinate signed events and publication gating.
    """
    if not callable(fetch):
        raise ValueError('fetch must be callable')
    first = _snapshot(fetch)
    if first != _snapshot(fetch):
        raise ValueError('unstable inventory')
    return {ident: name for ident, (name, private) in first.items() if not private}


def _policy_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('unsafe repository policy')
        data = stream.read(10_000_001)
        if len(data) > 10_000_000:
            raise ValueError('repository policy too large')
        doc = json.loads(data)
        if not isinstance(doc, dict) or set(doc) != {'repositories'}:
            raise ValueError('invalid repository policy')
        # Validate disabled identities too, as the file policy validator does.
        entries = doc['repositories']
        if not isinstance(entries, list):
            raise ValueError('invalid repository policy')
        identities = {}
        names = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {'id', 'full_name', 'enabled'} or type(entry['enabled']) is not bool:
                raise ValueError('invalid repository policy')
            ident, name = entry['id'], entry['full_name']
            allowed({ident: name})
            if ident in identities or name.casefold() in names:
                raise ValueError('duplicate repository policy')
            identities[ident] = name
            names.add(name.casefold())
        return data, stat.S_IMODE(info.st_mode), {e['id']: e['full_name'] for e in entries if e['enabled']}


def _replace_policy(path, data, mode):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.repos-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def invalidate_inventory(gate):
    """Pause publication and supersede any in-flight inventory snapshot."""
    from revocation_gate import locked_gate
    signal = secrets.token_hex(16)
    with locked_gate(gate) as directory:
        # Invalidate the in-flight sync before replacing its signal, even on crash.
        fd = os.open('inventory-paused', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as marker:
            marker.write(signal)
            marker.flush()
            os.fsync(marker.fileno())
        os.fsync(directory)
        name = '.signal-' + secrets.token_hex(16)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'w') as marker:
                marker.write(signal)
                marker.flush()
                os.fsync(marker.fileno())
            os.replace(name, 'inventory-signal', src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
    return signal


def _signal(directory):
    try:
        fd = os.open('inventory-signal', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd) as marker:
        return marker.read(33)


def reconcile_installation(auth, transport, gate, policy_path):
    from revocation_gate import locked_gate
    # ponytail: read under the gate; sync rechecks it before and after fetching.
    with locked_gate(gate) as directory:
        signal = _signal(directory)
    return sync_installation(auth, transport, gate, policy_path, signal=signal)


def sync_installation(auth, transport, gate, policy_path, *, signal=None):
    """Sync a complete public snapshot; all policy writers must share gate lock.

    Concurrent webhooks must also serialize against this sync or invalidate its
    gate revision. Two GitHub reads cannot provide a transactional snapshot.
    """
    from revocation_gate import locked_gate, _read_state, _version, _write_state
    if signal is not None and (not isinstance(signal, str) or len(signal) != 32
                               or any(c not in '0123456789abcdef' for c in signal)):
        raise ValueError('invalid installation signal')
    # ponytail: a persistent pause survives crashes and blocks every gate user.
    nonce = secrets.token_hex(16)
    with locked_gate(gate) as directory:
        if _signal(directory) != signal:
            raise SyncSuperseded('installation signal pending or superseded')
        fd = os.open('inventory-paused', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as marker:
            marker.write(nonce)
            marker.flush()
            os.fsync(marker.fileno())
        os.fsync(directory)
        # Capture the baseline under the same lock as the pause: a signal must
        # not be absorbed into a later baseline after the sync has started.
        old_data, mode, old_policy = _policy_bytes(policy_path)
        version = _version(_read_state(directory))
    started = int(time.time())
    token, _ = auth.inventory_token()
    snapshot = installation_snapshot(transport, token)
    new_data = json.dumps({'repositories': [
        {'id': ident, 'full_name': name, 'enabled': True}
        for ident, name in sorted(snapshot.items())]}, separators=(',', ':')).encode()
    with locked_gate(gate) as directory:
        if _signal(directory) != signal:
            raise SyncSuperseded('installation signal superseded')
        try:
            fd = os.open('inventory-paused', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            raise SyncSuperseded('installation sync superseded')
        with os.fdopen(fd) as marker:
            if marker.read(33) != nonce:
                raise SyncSuperseded('installation sync superseded')
        state = _read_state(directory)
        if _version(state) != version or _policy_bytes(policy_path)[:2] != (old_data, mode):
            raise ValueError('installation sync conflict')
        matches = lambda ident, name: snapshot.get(ident) == name and old_policy.get(ident) == name and state['policy'].get(str(ident)) == name
        approvals = [entry for entry in state['approvals'] if matches(entry[0], entry[1])]
        # ponytail: stage revocations before changing the file; additions wait
        # until both policy writes can agree, so a failed write cannot grant access.
        retained = {str(ident): name for ident, name in snapshot.items() if matches(ident, name)}
        auto = {key: name for key, name in state.get('auto_repos', {}).items() if key in retained}
        _write_state(directory, retained, approvals, auto)
        _replace_policy(policy_path, new_data, mode)
        public = {str(ident): name for ident, name in snapshot.items()}
        _write_state(directory, public, approvals, public)
        fd = os.open('inventory-valid', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as validity:
            validity.write(str(started))
            validity.flush()
            os.fsync(validity.fileno())
        # Persist the validity name before removing the durable pause.
        os.fsync(directory)
        os.unlink('inventory-paused', dir_fd=directory)
        if signal is not None:
            os.unlink('inventory-signal', dir_fd=directory)
        try:
            os.fsync(directory)
        except OSError:
            # ponytail: restore the pause if the final directory sync fails.
            fd = os.open('inventory-paused', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            os.close(fd)
            raise
    return snapshot
