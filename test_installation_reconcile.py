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
