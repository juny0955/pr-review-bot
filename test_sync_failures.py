import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import installation_inventory as inventory
import revocation_gate as gate


class SyncFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.gate = root / 'gate'
        self.gate.mkdir(mode=0o700)
        (self.gate / 'lock').touch(mode=0o600)
        self.policy = root / 'repos.json'
        self.policy.write_text(json.dumps({'repositories': [{'id': 1, 'full_name': 'a/one', 'enabled': True}]}))
        self.policy.chmod(0o600)
        self.identity = [1, 'a/one', 1, 'a'*40, 'b'*40, 'c'*64]
        trusted = patch('revocation_gate._trusted_directory', side_effect=lambda p: os.open(p, os.O_RDONLY | os.O_DIRECTORY))
        trusted.start()
        self.addCleanup(trusted.stop)
        gate.update_gate(self.gate, {'1': 'a/one'}, [self.identity], auto_repos={'1': 'a/one'})
        self.auth = Mock()
        self.auth.inventory_token.return_value = ('mock', 1)
        self.transport = Mock(return_value={'total_count': 1, 'repositories': [{'id': 1, 'full_name': 'a/one', 'private': False}]})

    def sync(self):
        inventory.sync_installation(self.auth, self.transport, self.gate, self.policy)

    def check_paused_and_recover(self):
        for auto in (False, True):
            with self.assertRaises(ValueError):
                with gate.authorize(self.gate, self.identity, single_vps_mvp=auto):
                    pass
        self.sync()
        with gate.authorize(self.gate, self.identity, single_vps_mvp=True):
            pass

    def test_write_failures_keep_pause_and_recover(self):
        original_state = gate._write_state
        original_replace = inventory._replace_policy
        for failure in ('first-state', 'policy', 'second-state', 'final-fsync'):
            with self.subTest(failure=failure):
                calls = 0
                def state(*args):
                    nonlocal calls
                    calls += 1
                    if failure == ('first-state' if calls == 1 else 'second-state'):
                        raise OSError('injected state failure')
                    return original_state(*args)
                real_fsync = os.fsync
                def fsync(fd):
                    if failure == 'final-fsync' and not (self.gate / 'inventory-paused').exists():
                        raise OSError('injected final fsync failure')
                    return real_fsync(fd)
                with patch.object(gate, '_write_state', side_effect=state), \
                     patch.object(inventory, '_replace_policy', side_effect=OSError('injected policy failure') if failure == 'policy' else original_replace), \
                     patch('os.fsync', side_effect=fsync), self.assertRaises(OSError):
                    self.sync()
                self.check_paused_and_recover()

    def test_valid_marker_is_durable_before_unlink_and_fsync_failure_keeps_pause(self):
        for signalled in (False, True):
            for fail in (False, True):
                with self.subTest(signalled=signalled, fail=fail):
                    (self.gate / 'inventory-valid').unlink(missing_ok=True)
                    signal = inventory.invalidate_inventory(self.gate) if signalled else None
                    real_fsync, real_unlink = os.fsync, os.unlink
                    valid_synced = directory_synced = False
                    def fsync(fd):
                        nonlocal valid_synced, directory_synced
                        info = os.fstat(fd)
                        valid = self.gate / 'inventory-valid'
                        if valid.exists() and info.st_ino == valid.stat().st_ino and info.st_dev == valid.stat().st_dev:
                            real_fsync(fd)
                            valid_synced = True
                            return
                        if valid_synced and (info.st_dev, info.st_ino) == (self.gate.stat().st_dev, self.gate.stat().st_ino):
                            if fail and not directory_synced:
                                raise OSError('injected validity directory fsync failure')
                            real_fsync(fd)
                            directory_synced = True
                            return
                        real_fsync(fd)
                    def unlink(path, *args, **kwargs):
                        if path in ('inventory-paused', 'inventory-signal'):
                            self.assertTrue(directory_synced, 'unlink before validity directory fsync')
                        return real_unlink(path, *args, **kwargs)
                    with patch('os.fsync', side_effect=fsync), patch('os.unlink', side_effect=unlink):
                        if fail:
                            with self.assertRaises(OSError):
                                inventory.sync_installation(self.auth, self.transport, self.gate, self.policy, signal=signal)
                        else:
                            inventory.sync_installation(self.auth, self.transport, self.gate, self.policy, signal=signal)
                    self.assertTrue(valid_synced)
                    if fail:
                        self.assertTrue((self.gate / 'inventory-paused').exists())
                        self.assertEqual((self.gate / 'inventory-signal').exists(), signalled)
                        with self.assertRaises(ValueError):
                            with gate.authorize(self.gate, self.identity, single_vps_mvp=True):
                                pass
                        inventory.reconcile_installation(self.auth, self.transport, self.gate, self.policy)
                    else:
                        self.assertTrue(directory_synced)
                        self.assertFalse((self.gate / 'inventory-paused').exists())
                        self.assertFalse((self.gate / 'inventory-signal').exists())

    def test_crash_before_and_after_pause_unlink(self):
        for after in (False, True):
            with self.subTest(after=after):
                (self.gate / 'inventory-valid').unlink(missing_ok=True)
                pid = os.fork()
                if pid == 0:
                    real_unlink = os.unlink
                    def crash(path, *args, **kwargs):
                        if path == 'inventory-paused':
                            if after:
                                real_unlink(path, *args, **kwargs)
                            os._exit(77)
                        return real_unlink(path, *args, **kwargs)
                    with patch('os.unlink', side_effect=crash):
                        self.sync()
                    os._exit(0)
                _, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 77)
                self.assertTrue((self.gate / 'inventory-valid').exists())
                self.assertEqual((self.gate / 'inventory-paused').exists(), not after)
                if not after:
                    self.check_paused_and_recover()
                else:
                    with gate.authorize(self.gate, self.identity, single_vps_mvp=True):
                        pass

    def test_failed_policy_write_revokes_before_file_and_retry_converges(self):
        before = self.policy.read_bytes()
        self.transport.return_value = {'total_count': 1, 'repositories': [
            {'id': 2, 'full_name': 'a/two', 'private': False}]}
        with patch.object(inventory, '_replace_policy', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.sync()
        self.assertEqual(self.policy.read_bytes(), before)
        state, _ = gate.gate_snapshot(self.gate)
        self.assertEqual(state['policy'], {})
        self.assertEqual(state['approvals'], [])
        self.assertEqual(state['auto_repos'], {})
        with self.assertRaises(ValueError):
            with gate.authorize(self.gate, self.identity, single_vps_mvp=True):
                pass
        self.sync()
        state, _ = gate.gate_snapshot(self.gate)
        self.assertEqual(state['policy'], {'2': 'a/two'})
        self.assertEqual(state['auto_repos'], {'2': 'a/two'})
        self.assertEqual(state['approvals'], [])
        self.assertEqual(json.loads(self.policy.read_bytes())['repositories'], [
            {'id': 2, 'full_name': 'a/two', 'enabled': True}])

    def test_process_death_during_each_policy_write_stays_paused(self):
        for boundary in (1, 2, 3):
            with self.subTest(boundary=boundary):
                pid = os.fork()
                if pid == 0:
                    original_state = gate._write_state
                    original_replace = inventory._replace_policy
                    step = [0]
                    def crash_after(fn):
                        def wrapped(*args):
                            fn(*args)
                            step[0] += 1
                            if step[0] == boundary:
                                os._exit(77)
                        return wrapped
                    gate._write_state = crash_after(original_state)
                    inventory._replace_policy = crash_after(original_replace)
                    self.sync()
                    os._exit(0)
                _, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 77)
                self.check_paused_and_recover()


if __name__ == '__main__':
    unittest.main()
