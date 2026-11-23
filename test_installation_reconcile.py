import json
import os
import subprocess
import tempfile
import unittest
import sqlite3
from contextlib import closing, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from installation_inventory import sync_installation
from repo_config import allowed
from revocation_gate import update_gate, gate_snapshot, authorize, locked_gate
from github_app_auth import InstallationAuth
from github_app_transport import installation_transport, inventory_transport


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.gate = self.root / 'gate'
        self.gate.mkdir(mode=0o700)
        (self.gate / 'lock').touch(mode=0o600)
        self.policy = self.root / 'repos.json'
        self.policy.write_text(json.dumps({'repositories': [
            {'id': 1, 'full_name': 'old/one', 'enabled': True},
            {'id': 2, 'full_name': 'old/two', 'enabled': True}]}))
        self.policy.chmod(0o600)
        self.approval = [1, 'old/one', 7, 'a'*40, 'b'*40, 'c'*64]
        self.trusted = patch('revocation_gate._trusted_directory', side_effect=lambda p: os.open(p, os.O_RDONLY | os.O_DIRECTORY))
        self.trusted.start()
        self.addCleanup(self.trusted.stop)
        update_gate(self.gate, {'1': 'old/one', '2': 'old/two'}, [self.approval], auto_repos={'1': 'old/one'})
        self.auth = Mock()
        self.auth.inventory_token.return_value = ('mock-token', 123)

    def sync(self, entries):
        transport = Mock(return_value={'total_count': len(entries), 'repositories': entries})
        sync_installation(self.auth, transport, self.gate, self.policy)
        self.assertEqual(transport.call_count, 2)

    def test_reconciler_recovers_crash_and_retries_new_signal(self):
        import multiprocessing
        import orchestrator
        from installation_inventory import invalidate_inventory
        ctx = multiprocessing.get_context('fork')
        first = invalidate_inventory(self.gate)
        def crash():
            def transport(*args): os._exit(37)
            sync_installation(self.auth, transport, self.gate, self.policy, signal=first)
        child = ctx.Process(target=crash)
        child.start(); child.join(10)
        if child.is_alive():
            child.terminate(); child.join()
        self.assertEqual(child.exitcode, 37)
        calls = []
        def transport(*args):
            calls.append(1)
            if len(calls) == 1:
                invalidate_inventory(self.gate)
            return {'total_count': 0, 'repositories': []}
        class Stop:
            count = 0
            def wait(self, interval):
                self.count += 1
                return self.count > 2
            def set(self):
                self.count = 3
        with patch.object(orchestrator, 'inventory_transport', transport):
            orchestrator.inventory_loop(self.auth, self.gate, self.policy, Stop())
        self.assertEqual(len(calls), 4)
        self.assertEqual(allowed(self.policy), {})
        self.assertFalse((self.gate / 'inventory-signal').exists())
        self.assertFalse((self.gate / 'inventory-paused').exists())

    def test_invalidation_crash_preserves_signal_and_supersedes_inflight(self):
        import multiprocessing
        from installation_inventory import invalidate_inventory, reconcile_installation, SyncSuperseded
        ctx = multiprocessing.get_context('fork')
        for existing in (False, True):
            for stage in ('open', 'write', 'file_fsync', 'rename', 'dir_fsync'):
                with self.subTest(existing=existing, stage=stage):
                    for name in ('inventory-signal', 'inventory-paused'):
                        (self.gate / name).unlink(missing_ok=True)
                    old = invalidate_inventory(self.gate) if existing else None
                    entered, resume = ctx.Event(), ctx.Event()
                    result = ctx.Queue()
                    def inflight():
                        def fetch(*args):
                            entered.set()
                            if not resume.wait(10): raise RuntimeError('timeout')
                            return {'total_count': 1, 'repositories': [{'id': 1, 'full_name': 'old/one', 'private': False}]}
                        try:
                            sync_installation(self.auth, fetch, self.gate, self.policy, signal=old)
                            result.put('completed')
                        except SyncSuperseded:
                            result.put('superseded')
                    process = ctx.Process(target=inflight)
                    process.start()
                    try:
                        self.assertTrue(entered.wait(10))
                        def crash():
                            import installation_inventory as inv
                            real_open, real_fsync, real_replace, real_fdopen = os.open, os.fsync, os.replace, os.fdopen
                            temp_fd = [-1]
                            renamed = [False]
                            def op(name, flags, *args, **kwargs):
                                if str(name).startswith('.signal-'):
                                    if stage == 'open': os._exit(37)
                                    fd = real_open(name, flags, *args, **kwargs)
                                    temp_fd[0] = fd
                                    return fd
                                return real_open(name, flags, *args, **kwargs)
                            def fdopen(fd, *args, **kwargs):
                                if fd == temp_fd[0] and stage == 'write':
                                    os.write(fd, b'partial')
                                    os._exit(37)
                                return real_fdopen(fd, *args, **kwargs)
                            def fsync(fd):
                                if fd == temp_fd[0] and stage == 'file_fsync': os._exit(37)
                                if renamed[0] and stage == 'dir_fsync': os._exit(37)
                                return real_fsync(fd)
                            def replace(*args, **kwargs):
                                if stage == 'rename': os._exit(37)
                                real_replace(*args, **kwargs)
                                renamed[0] = True
                            with patch.object(inv.os, 'open', side_effect=op), patch.object(inv.os, 'fdopen', side_effect=fdopen), patch.object(inv.os, 'fsync', side_effect=fsync), patch.object(inv.os, 'replace', side_effect=replace):
                                invalidate_inventory(self.gate)
                        child = ctx.Process(target=crash)
                        child.start(); child.join(10)
                        if child.is_alive(): child.terminate(); child.join()
                        self.assertEqual(child.exitcode, 37)
                        marker = self.gate / 'inventory-signal'
                        actual = marker.read_text() if marker.exists() else None
                        if stage != 'dir_fsync': self.assertEqual(actual, old)
                        else: self.assertRegex(actual or '', r'^[0-9a-f]{32}$')
                        with self.assertRaises(ValueError):
                            with authorize(self.gate, self.approval, single_vps_mvp=True): pass
                        resume.set(); process.join(10)
                        self.assertEqual(process.exitcode, 0)
                        self.assertEqual(result.get(timeout=2), 'superseded')
                        transport = Mock(return_value={'total_count': 0, 'repositories': []})
                        reconcile_installation(self.auth, transport, self.gate, self.policy)
                        self.assertEqual(transport.call_count, 2)
                        self.assertFalse(marker.exists())
                        self.assertFalse((self.gate / 'inventory-paused').exists())
                    finally:
                        resume.set()
                        if process.is_alive(): process.terminate(); process.join()
                        result.close()

    def test_reconciler_rejects_invalid_signal_without_fetching(self):
        from installation_inventory import reconcile_installation
        marker = self.gate / 'inventory-signal'
        for value in ('', 'f' * 31, 'g' * 32, 'f' * 33):
            marker.write_text(value)
            transport = Mock()
            with self.assertRaises(ValueError):
                reconcile_installation(self.auth, transport, self.gate, self.policy)
            transport.assert_not_called()
            self.assertEqual(marker.read_text(), value)
            with self.assertRaises(ValueError):
                with authorize(self.gate, self.approval, single_vps_mvp=True): pass

    def test_pending_signal_cannot_be_consumed_by_unrelated_sync(self):
        from installation_inventory import invalidate_inventory, SyncSuperseded
        entries = [{'id': 1, 'full_name': 'old/one', 'private': False}]
        self.sync(entries)
        signal = invalidate_inventory(self.gate)
        with self.assertRaises(SyncSuperseded):
            self.sync(entries)
        with self.assertRaises(ValueError):
            with authorize(self.gate, self.approval, single_vps_mvp=True): pass
        transport = Mock(return_value={'total_count': 0, 'repositories': []})
        sync_installation(self.auth, transport, self.gate, self.policy, signal=signal)
        with self.assertRaises(ValueError):
            with authorize(self.gate, self.approval, single_vps_mvp=True): pass

    def test_cross_process_signal_races_and_crash_recovery(self):
        import multiprocessing
        from installation_inventory import invalidate_inventory, SyncSuperseded
        ctx = multiprocessing.get_context('fork')
        entries = [{'id': 1, 'full_name': 'old/one', 'private': False}]
        self.sync(entries)
        entered, resume = ctx.Event(), ctx.Event()
        results = ctx.Queue()
        def background_sync():
            def transport(*args):
                entered.set()
                if not resume.wait(10):
                    raise RuntimeError('test timeout')
                return {'total_count': 1, 'repositories': entries}
            try:
                sync_installation(self.auth, transport, self.gate, self.policy)
                results.put('authorized')
            except SyncSuperseded:
                results.put('superseded')
        process = ctx.Process(target=background_sync)
        process.start()
        try:
            self.assertTrue(entered.wait(10))
            first = invalidate_inventory(self.gate)
            second = invalidate_inventory(self.gate)
            with self.assertRaises(SyncSuperseded):
                sync_installation(self.auth, Mock(), self.gate, self.policy, signal=first)
            resume.set()
            process.join(10)
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(results.get(timeout=2), 'superseded')
            with self.assertRaises(ValueError):
                with authorize(self.gate, self.approval, single_vps_mvp=True): pass
            def crash():
                def transport(*args): os._exit(37)
                sync_installation(self.auth, transport, self.gate, self.policy, signal=second)
            child = ctx.Process(target=crash)
            child.start(); child.join(10)
            self.assertEqual(child.exitcode, 37)
            with self.assertRaises(SyncSuperseded): self.sync(entries)
            with self.assertRaises(ValueError):
                with authorize(self.gate, self.approval, single_vps_mvp=True): pass
            recovery = invalidate_inventory(self.gate)
            transport = Mock(return_value={'total_count': 0, 'repositories': []})
            sync_installation(self.auth, transport, self.gate, self.policy, signal=recovery)
            with self.assertRaises(ValueError):
                with authorize(self.gate, self.approval, single_vps_mvp=True): pass
        finally:
            resume.set()
            if process.is_alive(): process.terminate(); process.join()
            results.close()

    def test_signal_sync_superseded_during_fetch_across_processes(self):
        import multiprocessing
        from installation_inventory import invalidate_inventory, SyncSuperseded
        ctx = multiprocessing.get_context('fork')
        entered, resume = ctx.Event(), ctx.Event()
        results = ctx.Queue()
        first = invalidate_inventory(self.gate)
        def receiver_sync():
            def transport(*args):
                entered.set()
                if not resume.wait(10): raise RuntimeError('test timeout')
                return {'total_count': 1, 'repositories': [{'id': 1, 'full_name': 'old/one', 'private': False}]}
            try:
                sync_installation(self.auth, transport, self.gate, self.policy, signal=first)
                results.put('completed')
            except SyncSuperseded:
                results.put('superseded')
        process = ctx.Process(target=receiver_sync)
        process.start()
        try:
            self.assertTrue(entered.wait(10))
            second = invalidate_inventory(self.gate)
            with self.assertRaises(SyncSuperseded): self.sync([])
            resume.set(); process.join(10)
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(results.get(timeout=2), 'superseded')
            with self.assertRaises(ValueError):
                with authorize(self.gate, self.approval, single_vps_mvp=True): pass
            transport = Mock(return_value={'total_count': 0, 'repositories': []})
            sync_installation(self.auth, transport, self.gate, self.policy, signal=second)
            self.assertEqual(allowed(self.policy), {})
        finally:
            resume.set()
            if process.is_alive(): process.terminate(); process.join()
            results.close()

    def test_full_sync_revokes_renames_and_private(self):
        self.sync([{'id': 1, 'full_name': 'new/one', 'private': False},
                   {'id': 2, 'full_name': 'old/two', 'private': True},
                   {'id': 3, 'full_name': 'new/three', 'private': False}])
        self.assertEqual(allowed(self.policy), {1: 'new/one', 3: 'new/three'})
        state, _ = gate_snapshot(self.gate)
        self.assertEqual(state['policy'], {'1': 'new/one', '3': 'new/three'})
        self.assertEqual(state['approvals'], [])
        self.assertEqual(state['auto_repos'], {'1': 'new/one', '3': 'new/three'})
        with self.assertRaises(ValueError):
            with authorize(self.gate, self.approval, single_vps_mvp=True): pass

    def test_fetch_failure_and_incomplete_preserve(self):
        before = self.policy.read_bytes(), gate_snapshot(self.gate)
        for transport in [Mock(side_effect=RuntimeError('failure')), Mock(return_value={'total_count': 2, 'repositories': []})]:
            with self.assertRaises((RuntimeError, ValueError)):
                sync_installation(self.auth, transport, self.gate, self.policy)
            self.assertEqual((self.policy.read_bytes(), gate_snapshot(self.gate)), before)

    def test_failure_pauses_all_publishers_until_successful_recovery(self):
        before = self.policy.read_bytes(), gate_snapshot(self.gate)
        with self.assertRaises(RuntimeError):
            sync_installation(self.auth, Mock(side_effect=RuntimeError('offline')), self.gate, self.policy)
        self.assertEqual((self.policy.read_bytes(), gate_snapshot(self.gate)), before)
        with self.assertRaises(ValueError):
            with authorize(self.gate, self.approval, single_vps_mvp=True): pass
        with self.assertRaises(ValueError):
            with authorize(self.gate, self.approval): pass
        self.sync([{'id': 1, 'full_name': 'old/one', 'private': False}])
        with authorize(self.gate, self.approval, single_vps_mvp=True): pass

    def test_missing_second_page_preserves(self):
        before = self.policy.read_bytes(), gate_snapshot(self.gate)
        entries = [{'id': i, 'full_name': f'a/r{i}', 'private': False} for i in range(1, 101)]
        def transport(token, path):
            return {'total_count': 101, 'repositories': entries if path.endswith('page=1') else []}
        with self.assertRaises(ValueError):
            sync_installation(self.auth, transport, self.gate, self.policy)
        self.assertEqual((self.policy.read_bytes(), gate_snapshot(self.gate)), before)

    def test_successful_snapshot_expires_without_refresh(self):
        with patch('time.time', return_value=1000):
            self.sync([{'id': 1, 'full_name': 'old/one', 'private': False}])
        with patch('time.time', return_value=1121), self.assertRaises(ValueError):
            with authorize(self.gate, self.approval, single_vps_mvp=True): pass

    def test_baseline_is_captured_under_pause_lock_and_signal_supersedes_sync(self):
        from installation_inventory import _policy_bytes
        def read_policy(path):
            with self.assertRaises(TimeoutError):
                with locked_gate(self.gate, timeout=0): pass
            return _policy_bytes(path)
        signals = []
        def signal(*args):
            from installation_inventory import invalidate_inventory
            signals.append(invalidate_inventory(self.gate))
            return {'total_count': 0, 'repositories': []}
        before = self.policy.read_bytes(), gate_snapshot(self.gate)
        with patch('installation_inventory._policy_bytes', side_effect=read_policy):
            with self.assertRaisesRegex(ValueError, 'superseded'):
                sync_installation(self.auth, signal, self.gate, self.policy)
        self.assertEqual((self.policy.read_bytes(), gate_snapshot(self.gate)), before)
        with self.assertRaises(ValueError):
            with authorize(self.gate, self.approval, single_vps_mvp=True): pass
        transport = Mock(return_value={'total_count': 1, 'repositories': [{'id': 1, 'full_name': 'old/one', 'private': False}]})
        sync_installation(self.auth, transport, self.gate, self.policy, signal=signals[-1])
        with authorize(self.gate, self.approval, single_vps_mvp=True): pass

    def test_policy_conflict_preserves_gate(self):
        before = gate_snapshot(self.gate)
        def transport(*args):
            self.policy.write_text('{"repositories": []}')
            return {'total_count': 0, 'repositories': []}
        with self.assertRaises(ValueError):
            sync_installation(self.auth, transport, self.gate, self.policy)
        self.assertEqual(gate_snapshot(self.gate), before)

    def test_revocation_precedes_policy_under_gate_lock(self):
        def replace(*args):
            with self.assertRaises(TimeoutError):
                with locked_gate(self.gate, timeout=0): pass
            raise OSError('stop after gate update')
        with patch('installation_inventory._replace_policy', side_effect=replace), self.assertRaises(OSError):
            self.sync([])
        self.assertEqual(gate_snapshot(self.gate)[0]['policy'], {})

    def test_unchanged_identity_retains_existing_approval(self):
        self.sync([{'id': 1, 'full_name': 'old/one', 'private': False}])
        state, _ = gate_snapshot(self.gate)
        self.assertEqual(state['approvals'], [self.approval])
        self.assertEqual(state['auto_repos'], {'1': 'old/one'})

    def test_gate_conflict_preserves_concurrent_update(self):
        def transport(*args):
            state, version = gate_snapshot(self.gate)
            update_gate(self.gate, {}, [], expected=version)
            return {'total_count': 0, 'repositories': []}
        before = self.policy.read_bytes()
        with self.assertRaises(ValueError):
            sync_installation(self.auth, transport, self.gate, self.policy)
        self.assertEqual(self.policy.read_bytes(), before)
        self.assertEqual(gate_snapshot(self.gate)[0]['policy'], {})

    def test_policy_write_failure_still_revokes(self):
        with patch('installation_inventory._replace_policy', side_effect=OSError('fail')):
            with self.assertRaises(OSError):
                self.sync([])
        self.assertEqual(allowed(self.policy), {1: 'old/one', 2: 'old/two'})
        self.assertEqual(gate_snapshot(self.gate)[0]['policy'], {})


    def test_end_to_end_mocked_auth_transport_and_sync(self):
        key = self.root / 'mock-key'
        key.write_bytes(b'not a real key')
        key.chmod(0o600)
        auth = InstallationAuth(1, 2, key, self.policy, 'read', installation_transport, clock=lambda: 1700000000)
        def rsa(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, b'Modulus=' + b'F'*512 + b'\n' if '-modulus' in args else b'x'*256)
        def request(method, path, credential, body=None):
            if method == 'POST':
                self.assertEqual(body, {'permissions': {'metadata': 'read'}})
                return {'token': 'mock-token', 'expires_at': '2023-11-14T22:43:20Z', 'permissions': {'metadata': 'read'}}
            self.assertEqual(credential, 'mock-token')
            return {'total_count': 1, 'repositories': [{'id': 44, 'full_name': 'any/public', 'private': False}]}
        with patch('github_app_auth.subprocess.run', side_effect=rsa), patch('github_app_transport._request', side_effect=request) as api:
            self.assertEqual(sync_installation(auth, inventory_transport, self.gate, self.policy), {44: 'any/public'})
        self.assertEqual(api.call_count, 3)
        self.assertEqual(allowed(self.policy), {44: 'any/public'})
        self.assertEqual(gate_snapshot(self.gate)[0]['policy'], {'44': 'any/public'})
        self.assertEqual(gate_snapshot(self.gate)[0]['auto_repos'], {'44': 'any/public'})

    def test_worker_policy_and_gate_follow_inventory(self):
        from receiver import create_server
        from worker import Worker
        from test_worker import FakeGH, FakeModel, payload, sign_queue
        db = self.root / 'queue.db'
        with patch('receiver.ThreadingHTTPServer'):
            server = create_server('secret', self.policy, str(db), 0)
        server.server_close()
        wiki = self.root / 'wiki'
        wiki.mkdir()
        (wiki / 'guide.md').write_text('Review evidence')
        model = FakeModel()
        worker = Worker(str(db), FakeGH(), model, wiki, self.policy, webhook_secret='secret')
        entry = {'id': 123, 'full_name': 'example-owner/example-repo', 'private': False}
        self.sync([entry])
        identity = [123, entry['full_name'], 1, 'a'*40, 'b'*40, 'c'*64]
        state, version = gate_snapshot(self.gate)
        update_gate(self.gate, state['policy'], [identity], expected=version)
        with authorize(self.gate, identity):
            pass
        def enqueue(delivery):
            data = payload()
            data['sender'] = {'id': 999, 'login': 'outside-contributor'}
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('INSERT INTO queue(delivery_id,body) VALUES (?,?)', (delivery, json.dumps(data).encode()))
                sign_queue(conn, delivery, 'secret')
        enqueue('first')
        self.assertEqual(worker.run_once()['status'], 'done')
        self.assertEqual(len(model.calls), 1)
        self.sync([])
        with self.assertRaises(ValueError):
            with authorize(self.gate, identity):
                pass
        enqueue('second')
        self.assertEqual(worker.run_once()['status'], 'skipped')
        self.assertEqual(len(model.calls), 1)

    def test_orchestrator_start_restart_and_api_failure(self):
        import orchestrator
        db = self.root / 'db'
        db.touch()
        github = Mock(auth=self.auth)
        entries = [{'id': 123, 'full_name': 'example-owner/example-repo', 'private': False}]
        transport = Mock(return_value={'total_count': 1, 'repositories': entries})
        args = ['--db', str(db), '--wiki', str(self.root), '--repos', str(self.policy),
                '--dry-run', '--enable-direct-inference', '--authorize-wiki-transfer',
                '--github-app-read', '--publication-gate', str(self.gate), '--sync-installation']
        def run(worker, stop):
            self.assertEqual(allowed(self.policy), {123: 'example-owner/example-repo'})
            self.assertEqual(gate_snapshot(self.gate)[0]['policy'], {'123': 'example-owner/example-repo'})
        import threading
        original_join = threading.Thread.join
        with patch.dict(os.environ, {'WEBHOOK_SECRET': 'secret'}), \
             patch.object(orchestrator, 'app_read_auth', return_value=self.auth), \
             patch.object(orchestrator, 'GitHubReadOnly', return_value=github), \
             patch.object(orchestrator, 'inventory_transport', transport), \
             patch.object(orchestrator, 'resolve_hermes_direct_adapter'), \
             patch.object(orchestrator, 'Worker'), patch.object(orchestrator, 'run_loop', side_effect=run), \
             patch.object(orchestrator.threading.Thread, 'join', autospec=True, side_effect=original_join) as join, \
             redirect_stdout(StringIO()):
            from installation_inventory import invalidate_inventory
            invalidate_inventory(self.gate)
            self.assertEqual(orchestrator.main(args), 0)
            self.assertEqual(orchestrator.main(args), 0)
            self.assertEqual(join.call_count, 2)
            before = self.policy.read_bytes(), gate_snapshot(self.gate)
            transport.side_effect = RuntimeError('secret details')
            self.assertEqual(orchestrator.main(args), 1)
            self.assertEqual((self.policy.read_bytes(), gate_snapshot(self.gate)), before)

    def test_poll_error_preserves_policy_and_stops(self):
        import orchestrator
        class Stop:
            count = 0
            def wait(self, interval):
                self.count += 1
                return self.count > 2
            def set(self):
                self.count = 3
        before = self.policy.read_bytes(), gate_snapshot(self.gate)
        transport = Mock(side_effect=RuntimeError('secret details'))
        with patch.object(orchestrator, 'inventory_transport', transport), redirect_stdout(StringIO()) as output:
            orchestrator.inventory_loop(self.auth, self.gate, self.policy, Stop())
        self.assertEqual(output.getvalue(), '{"status": "inventory_error"}\n')
        self.assertEqual((self.policy.read_bytes(), gate_snapshot(self.gate)), before)
        self.assertEqual(transport.call_count, 1)


if __name__ == '__main__': unittest.main()
