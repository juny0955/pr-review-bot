from contextlib import closing
import hashlib
import hmac
import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

def payload(**changes):
    value = {'repository': {'id': 123, 'full_name': 'acme/repo'}, 'action': 'opened',
             'number': 1, 'pull_request': {'number': 1, 'draft': False,
                                            'state': 'open', 'head': {'sha': 'a' * 40}}}
    value.update(changes)
    return json.dumps(value).encode()

class ReceiverTest(unittest.TestCase):
    def test_signed_delivery_is_durable_and_deduplicated(self):
        from receiver import create_server
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / 'queue.db')
            server = create_server('secret', {123: 'acme/repo'}, db, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = payload()
                signature = 'sha256=' + hmac.new(b'secret', body, hashlib.sha256).hexdigest()
                headers = {'X-Hub-Signature-256': signature, 'X-GitHub-Event': 'pull_request', 'X-GitHub-Delivery': 'delivery-1'}
                def send(data, h):
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                    conn.request('POST', '/webhook', data, h)
                    response = conn.getresponse(); response.read(); conn.close()
                    return response.status
                self.assertEqual(send(body, headers), 202)
                self.assertEqual(send(body, headers), 200)
                with closing(sqlite3.connect(db)) as conn, conn:
                    self.assertEqual(conn.execute('SELECT delivery_id, body FROM queue').fetchall(), [('delivery-1', body)])
                    self.assertEqual(conn.execute('SELECT delivery_id, signature FROM webhook_signatures').fetchall(), [('delivery-1', signature)])
            finally:
                server.shutdown(); server.server_close(); thread.join()

class SecurityTest(unittest.TestCase):
    def setUp(self):
        from receiver import create_server
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / 'queue.db')
        self.server = create_server('secret', {123: 'acme/repo'}, self.db, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.tmp.cleanup()

    def send(self, body=None, overrides=None):
        if body is None: body = payload()
        headers = {'X-Hub-Signature-256': 'sha256=' + hmac.new(b'secret', body, hashlib.sha256).hexdigest(), 'X-GitHub-Event': 'pull_request', 'X-GitHub-Delivery': 'test-id'}
        headers.update(overrides or {})
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        conn.request('POST', '/webhook', body, headers)
        response = conn.getresponse(); response.read(); conn.close()
        return response.status

    def test_rejects_name_spoof_and_accepts_matching_identity(self):
        self.assertEqual(self.send(payload(repository={'id': 999, 'full_name': 'acme/repo'})), 403)
        self.assertEqual(self.send(payload(repository={'id': 123, 'full_name': 'evil/repo'})), 403)
        self.assertEqual(self.send(), 202)

    def test_rejects_bad_signature_and_body_tampering(self):
        self.assertEqual(self.send(overrides={'X-Hub-Signature-256': 'sha256=' + '0' * 64}), 401)
        self.assertEqual(self.send(overrides={'X-Hub-Signature-256': 'sha1=abc'}), 401)

    def test_rejects_unauthorized_repo_and_wrong_event(self):
        self.assertEqual(self.send(b'{"repository":{"full_name":"evil/repo"}}'), 403)
        self.assertEqual(self.send(overrides={'X-GitHub-Event': 'push'}), 400)

    def test_rejects_bad_json_and_invalid_delivery(self):
        self.assertEqual(self.send(b'['), 400)
        self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'bad id'}), 400)

    def test_delivery_conflict_does_not_replace_original(self):
        self.assertEqual(self.send(), 202)
        self.assertEqual(self.send(payload(action='reopened')), 409)
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 1)

    def test_replay_with_new_delivery_id_is_not_enqueued(self):
        self.assertEqual(self.send(), 202)
        self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'other-id'}), 200)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 1)

    def test_semantic_dedup_concurrent_restart_and_security(self):
        from receiver import create_server
        pr = json.loads(payload())['pull_request']
        pr.update(base={'sha': 'b' * 40}, updated_at='2026-01-02T03:04:05Z')
        bodies = [payload(pull_request=pr), payload(pull_request=pr, installation={'id': 42})]
        barrier = threading.Barrier(3)
        statuses = []
        def send(i):
            barrier.wait()
            statuses.append(self.send(bodies[i], {'X-GitHub-Delivery': f'concurrent-{i}'}))
        threads = [threading.Thread(target=send, args=(i,)) for i in range(2)]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join()
        self.assertEqual(sorted(statuses), [200, 202])
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.server = create_server('secret', {123: 'acme/repo'}, self.db, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.assertEqual(self.send(bodies[1], {'X-GitHub-Delivery': 'third', 'X-Hub-Signature-256': 'sha256=' + '0' * 64}), 401)
        self.assertEqual(self.send(bodies[1], {'X-GitHub-Delivery': 'third'}), 200)
        self.assertEqual(self.send(payload(action='reopened', pull_request=pr), {'X-GitHub-Delivery': 'third'}), 409)
        pr['updated_at'] = '2026-01-02T03:04:06Z'
        self.assertEqual(self.send(payload(pull_request=pr), {'X-GitHub-Delivery': 'new-event'}), 202)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT count(*) FROM webhook_semantic').fetchone()[0], 2)

    def test_fixed_installation_and_exact_deduplication(self):
        from receiver import create_server
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.server = create_server('secret', {123: 'acme/repo'}, self.db, port=0, installation_id=42)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        for installation in (None, {}, {'id': True}, {'id': '42'}, {'id': 43}, [], 42):
            with self.subTest(installation=installation):
                self.assertEqual(self.send(payload(installation=installation)), 403)
        self.assertEqual(self.send(b'[]'), 400)
        body = payload(installation={'id': 42})
        self.assertEqual(self.send(body), 202)
        self.assertEqual(self.send(body), 200)
        self.assertEqual(self.send(body, {'X-GitHub-Delivery': 'other'}), 200)
        self.assertEqual(self.send(payload(installation={'id': 42}, action='reopened')), 409)
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute('SELECT delivery_id, body FROM queue').fetchall(), [('test-id', body)])
            db.execute('DELETE FROM queue')
            db.execute('INSERT INTO tombstone VALUES (?, ?)', ('test-id', hashlib.sha256(body).digest()))
        self.assertEqual(self.send(body), 200)
        self.assertEqual(self.send(body, {'X-GitHub-Delivery': 'other'}), 200)
        self.assertEqual(self.send(payload(installation={'id': 42}, action='reopened')), 409)

    def test_fixed_installation_legacy_app_and_new_repo(self):
        from receiver import create_server
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        policy = Path(self.tmp.name) / 'repos.json'
        entries = [{'id': 123, 'full_name': 'acme/repo', 'enabled': True}]
        policy.write_text(json.dumps({'repositories': entries}))
        self.server = create_server('secret', str(policy), self.db, port=0, installation_id=42)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        pr = json.loads(payload())['pull_request']
        pr.update(base={'sha': 'b' * 40}, updated_at='2026-01-02T03:04:05Z')
        legacy = payload(pull_request=pr)
        app = payload(pull_request=pr, installation={'id': 42})
        self.assertEqual(self.send(legacy, {'X-Hub-Signature-256': 'sha256=' + '0' * 64}), 401)
        self.assertEqual(self.send(payload(pull_request=pr, installation={'id': 43})), 403)
        self.assertEqual(self.send(legacy), 202)
        self.assertEqual(self.send(app, {'X-GitHub-Delivery': 'app'}), 200)
        new = payload(repository={'id': 456, 'full_name': 'acme/new'}, pull_request=pr, installation={'id': 42})
        self.assertEqual(self.send(new, {'X-GitHub-Delivery': 'new'}), 403)
        entries.append({'id': 456, 'full_name': 'acme/new', 'enabled': True})
        policy.write_text(json.dumps({'repositories': entries}))
        self.assertEqual(self.send(new, {'X-GitHub-Delivery': 'new'}), 202)
        self.assertEqual(self.send(payload(repository={'id': 456, 'full_name': 'acme/new'}, pull_request=pr), {'X-GitHub-Delivery': 'new-legacy'}), 200)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 2)

    def test_signed_installation_sync_and_unknown_repo(self):
        from receiver import create_server
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        policy = Path(self.tmp.name) / 'repos.json'
        policy.write_text(json.dumps({'repositories': [{'id': 123, 'full_name': 'acme/repo', 'enabled': True}]}))
        calls = []
        invalidations = []
        def sync(*, signal=None):
            calls.append(signal)
            policy.write_text(json.dumps({'repositories': [{'id': 456, 'full_name': 'acme/new', 'enabled': True}]}))
            return {456: 'acme/new'}
        def invalidate():
            nonce = str(len(invalidations) + 1)
            invalidations.append(nonce)
            return nonce
        self.server = create_server('secret', str(policy), self.db, port=0, installation_id=42, sync_inventory=sync, invalidate_inventory=invalidate)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        change = json.dumps({'installation': {'id': 42}, 'action': 'added'}).encode()
        headers = {'X-GitHub-Event': 'installation_repositories'}
        self.assertEqual(self.send(change, dict(headers, **{'X-Hub-Signature-256': 'sha256=' + '0' * 64})), 401)
        self.assertEqual(self.send(json.dumps({'installation': {'id': 43}, 'action': 'added'}).encode(), headers), 403)
        self.assertEqual(calls, [])
        self.assertEqual(invalidations, [])
        new = payload(repository={'id': 456, 'full_name': 'acme/new'}, installation={'id': 42})
        self.assertEqual(self.send(new), 202)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.send(change, headers), 200)
        self.assertEqual(self.send(change, {'X-GitHub-Event': 'installation'}), 200)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(invalidations), 2)
        self.assertEqual(calls, [None, '1', '2'])
        self.assertEqual(self.send(new, {'X-GitHub-Delivery': 'again'}), 200)

    def test_unknown_repository_requires_verified_inventory(self):
        from receiver import create_server
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        from unittest.mock import Mock
        sync = Mock(side_effect=[{}, RuntimeError('offline')])
        self.server = create_server('secret', {123: 'acme/repo'}, self.db, port=0, installation_id=42, sync_inventory=sync)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        new = payload(repository={'id': 456, 'full_name': 'acme/new'}, installation={'id': 42})
        self.assertEqual(self.send(new), 403)
        self.assertEqual(self.send(new), 503)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 0)

    def test_installation_configuration_fails_closed(self):
        from receiver import create_server, main
        for invalid in (True, 0, -1, '42', 2**63):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                create_server('secret', {123: 'acme/repo'}, self.db, port=0, installation_id=invalid)
        for invalid in ('', ' 42', '+42', '0', str(2**63)):
            with self.subTest(invalid=invalid), patch('receiver.allowed', return_value={123: 'acme/repo'}), patch.dict('os.environ', {'GITHUB_APP_INSTALLATION_ID': invalid, 'WEBHOOK_SECRET': 'secret', 'REPO_CONFIG': 'unused', 'QUEUE_DB': self.db}), self.assertRaises(ValueError):
                main()

    def test_rejects_malformed_pr_fields(self):
        invalid = [payload(action='changed'), payload(action=[]), payload(number=True),
                   payload(number=0), payload(pull_request={}),
                   payload(pull_request={'number': 2, 'draft': False, 'state': 'open', 'head': {'sha': 'a'*40}}),
                   payload(pull_request={'number': 1, 'draft': 0, 'state': 'open', 'head': {'sha': 'a'*40}}),
                   payload(pull_request={'number': 1, 'draft': False, 'state': 'open', 'head': {'sha': 'bad'}})]
        for body in invalid:
            with self.subTest(body=body): self.assertEqual(self.send(body), 400)

    def test_full_queue_rejects_new_body_but_accepts_replay(self):
        with patch('receiver.MAX_QUEUE', 1, create=True):
            self.assertEqual(self.send(), 202)
            self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'other'}), 200)
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)

    def test_capacity_check_is_atomic_for_concurrent_deliveries(self):
        barrier = threading.Barrier(3)
        statuses = []
        def send(action):
            barrier.wait()
            statuses.append(self.send(payload(action=action), {'X-GitHub-Delivery': action}))
        with patch('receiver.MAX_QUEUE', 1):
            threads = [threading.Thread(target=send, args=(action,)) for action in ('opened', 'reopened')]
            for thread in threads: thread.start()
            barrier.wait()
            for thread in threads: thread.join()
        self.assertEqual(sorted(statuses), [202, 503])
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM webhook_signatures').fetchone()[0], 1)

    def test_full_queue_preserves_terminal_rows_with_untrusted_modes(self):
        from worker import Worker, mode_provenance
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
        claim = worker.claim()
        self.assertTrue(worker.finish(claim[0], claim[2], 'failed', {'status': 'failed'}))
        for status in ('failed', 'skipped'):
            for publish, notifications, provenance in ((None, None, None), (0, 0, None),
                    (0, 0, '0' * 64), (1, 0, mode_provenance('secret', 'test-id', payload(), 0, 0)),
                    (0, 0, mode_provenance('secret', 'test-id', payload(), 0, 0))):
                with self.subTest(status=status, provenance=provenance, publish=publish):
                    with closing(sqlite3.connect(self.db)) as db, db:
                        db.execute('UPDATE work SET status=?,completed_at=0,publish_eligible=?,notifications_enabled=?,mode_provenance=?', (status, publish, notifications, provenance))
                        db.execute("UPDATE outbox SET status='sent'")
                        before = [db.execute('SELECT * FROM ' + table).fetchall() for table in ('queue', 'work', 'webhook_signatures', 'outbox', 'tombstone')]
                    with patch('receiver.MAX_QUEUE', 1):
                        self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
                        self.assertEqual(self.send(), 200)
                        self.assertEqual(self.send(payload(action='reopened')), 409)
                    with closing(sqlite3.connect(self.db)) as db:
                        self.assertEqual([db.execute('SELECT * FROM ' + table).fetchall() for table in ('queue', 'work', 'webhook_signatures', 'outbox', 'tombstone')], before)

    def test_old_done_result_is_not_evicted_even_after_notifications_sent(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
        claim = worker.claim()
        self.assertTrue(worker.finish(claim[0], claim[2], 'done', {'status': 'done'}))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET completed_at=0')
            db.execute("UPDATE outbox SET status='sent'")
        with patch('receiver.MAX_QUEUE', 1):
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT status FROM work').fetchone(), ('done',))
            self.assertIsNotNone(db.execute('SELECT body FROM queue').fetchone())

    def test_completed_work_retention_preserves_replay_and_delivery_conflict(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
        claim = worker.claim()
        self.assertTrue(worker.finish(claim[0], claim[2], 'failed', {'status': 'failed'}))
        from outbox import Outbox
        messages = []
        box = Outbox(self.db, repos={123: 'acme/repo'}, webhook_secret='secret')
        for _ in range(3):
            self.assertEqual(box.send_once(messages.append), 'sent')
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET completed_at=0')
        with patch('receiver.MAX_QUEUE', 1):
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
            self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'alias'}), 200)
            self.assertEqual(self.send(payload(action='reopened')), 409)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertIsNotNone(db.execute("SELECT 1 FROM queue WHERE delivery_id='test-id'").fetchone())
            self.assertEqual(db.execute("SELECT event,repo_id,repo_name,pr_number FROM outbox WHERE delivery_id='test-id' ORDER BY id").fetchall(),
                             [('detected', 123, 'acme/repo', 1), ('started', 123, 'acme/repo', 1), ('failed', 123, 'acme/repo', 1)])
        self.assertTrue(all('acme/repo #1' in message for message in messages))

    def test_cleanup_preserves_every_unsent_outbox_source(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
        claim = worker.claim()
        assert claim is not None
        self.assertTrue(worker.finish(claim[0], claim[2], 'done', {'status': 'done'}))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET completed_at=0')
        for status, name in [('failed', '@everyone'), ('pending', 'acme/repo'), ('sending', 'acme/repo'),
                             ('pending', '@everyone'), ('failed', 'acme/repo'), ('unknown', 'acme/repo')]:
            with self.subTest(status=status, name=name):
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute("UPDATE outbox SET status='sent'")
                    db.execute("UPDATE outbox SET status=?,repo_name=? WHERE event='started'", (status, name))
                    before = db.execute('SELECT * FROM outbox ORDER BY id').fetchall()
                    work = db.execute('SELECT * FROM work').fetchall()
                with patch('receiver.MAX_QUEUE', 1):
                    self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
                with closing(sqlite3.connect(self.db)) as db:
                    self.assertEqual(db.execute('SELECT delivery_id,body FROM queue').fetchall(), [('test-id', payload())])
                    self.assertEqual(db.execute('SELECT * FROM outbox ORDER BY id').fetchall(), before)
                    self.assertEqual(db.execute('SELECT * FROM work').fetchall(), work)
                    self.assertEqual(db.execute('SELECT count(*) FROM tombstone').fetchone()[0], 0)

    def test_cleanup_preserves_unresolved_outbox_source(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
        claim = worker.claim()
        assert claim is not None
        self.assertTrue(worker.finish(claim[0], claim[2], 'done', {'status': 'done'}))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET completed_at=0')
            db.execute("UPDATE outbox SET repo_name=NULL WHERE event='started'")
        with patch('receiver.MAX_QUEUE', 1):
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertIsNotNone(db.execute("SELECT body FROM queue WHERE delivery_id='test-id'").fetchone())

    def test_recent_terminal_results_are_preserved(self):
        from worker import Worker
        for status in ('done', 'failed', 'skipped'):
            with self.subTest(status=status):
                body = payload(action='opened' if status == 'done' else 'reopened', number=1 if status != 'skipped' else 2,
                               pull_request={'number': 1 if status != 'skipped' else 2, 'draft': False, 'state': 'open', 'head': {'sha': 'a' * 40}})
                delivery = status
                self.assertEqual(self.send(body, {'X-GitHub-Delivery': delivery}), 202)
                worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
                claim = worker.claim()
                self.assertTrue(worker.finish(claim[0], claim[2], status, {'status': status}))
                with patch('receiver.MAX_QUEUE', 1):
                    self.assertEqual(self.send(payload(action='synchronize'), {'X-GitHub-Delivery': 'new'}), 503)
                with closing(sqlite3.connect(self.db)) as db, db:
                    self.assertEqual(db.execute('SELECT status FROM work').fetchone()[0], status)
                    db.execute('DELETE FROM work'); db.execute('DELETE FROM queue')

    def test_insert_integrity_error_rolls_back_transaction(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
        claim = worker.claim()
        self.assertTrue(worker.finish(claim[0], claim[2], 'failed', {'status': 'failed'}))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET completed_at=0')
            db.execute("UPDATE outbox SET status='sent'")
            before = db.execute('SELECT * FROM work').fetchall()
            db.execute("CREATE TRIGGER reject_insert BEFORE INSERT ON queue BEGIN SELECT RAISE(ABORT, 'fail'); END")
        with patch('receiver.MAX_QUEUE', 2):
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
            with closing(sqlite3.connect(self.db)) as db, db:
                self.assertEqual(db.execute('SELECT delivery_id, body FROM queue').fetchall(), [('test-id', payload())])
                self.assertEqual(db.execute('SELECT * FROM work').fetchall(), before)
                self.assertEqual(db.execute('SELECT count(*) FROM tombstone').fetchone()[0], 0)
                db.execute('DROP TRIGGER reject_insert')
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 202)

    def test_full_queue_and_restart_preserve_replay(self):
        from worker import Worker
        from receiver import create_server
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
        claim = worker.claim()
        self.assertTrue(worker.finish(claim[0], claim[2], 'failed', {'status': 'failed'}))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET completed_at=0')
            db.execute("UPDATE outbox SET status='sent'")
            db.execute("CREATE TRIGGER reject_cleanup BEFORE DELETE ON queue BEGIN SELECT RAISE(ABORT, 'fail'); END")
        with patch('receiver.MAX_QUEUE', 1):
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
            with closing(sqlite3.connect(self.db)) as db, db:
                self.assertEqual(db.execute('SELECT count(*) FROM tombstone').fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT count(*) FROM work').fetchone()[0], 1)
                db.execute('DROP TRIGGER reject_cleanup')
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
            server = create_server('secret', {123: 'acme/repo'}, self.db, port=0)
            server.server_close()
            self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'alias'}), 200)

    def test_full_queue_never_evicts_running_or_retry_work(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'}, webhook_secret='secret')
        claim = worker.claim()
        with patch('receiver.MAX_QUEUE', 1):
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
            self.assertTrue(worker.finish(claim[0], claim[2], 'retry', {'status': 'retry'}))
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)

    def test_existing_database_permissions_are_restricted(self):
        from receiver import create_server
        import os
        os.chmod(self.db, 0o666)
        server = create_server('secret', {123: 'acme/repo'}, self.db, port=0)
        server.server_close()
        self.assertEqual(os.stat(self.db).st_mode & 0o777, 0o600)

    def test_requires_configuration(self):
        from receiver import create_server
        with self.assertRaises(ValueError): create_server('', {123: 'acme/repo'}, self.db, 0)
        with self.assertRaises(ValueError): create_server('secret', set(), self.db, 0)

if __name__ == '__main__': unittest.main()
