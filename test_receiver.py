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

    def test_completed_work_cleanup_preserves_replay_and_delivery_conflict(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'})
        claim = worker.claim()
        self.assertTrue(worker.finish(claim[0], claim[2], 'done', {'status': 'done'}))
        from outbox import Outbox
        messages = []
        box = Outbox(self.db, repos={123: 'acme/repo'})
        for _ in range(3):
            self.assertEqual(box.send_once(messages.append), 'sent')
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET completed_at=0')
        with patch('receiver.MAX_QUEUE', 1):
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 202)
            self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'alias'}), 200)
            self.assertEqual(self.send(payload(action='reopened')), 409)
        from outbox import Outbox
        with closing(sqlite3.connect(self.db)) as db:
            self.assertIsNone(db.execute("SELECT 1 FROM queue WHERE delivery_id='test-id'").fetchone())
            self.assertEqual(db.execute("SELECT event,repo_id,repo_name,pr_number FROM outbox WHERE delivery_id='test-id' ORDER BY id").fetchall(),
                             [('detected', 123, 'acme/repo', 1), ('started', 123, 'acme/repo', 1), ('completed', 123, 'acme/repo', 1)])
        self.assertTrue(all('acme/repo #1' in message for message in messages))

    def test_cleanup_preserves_every_unsent_outbox_source(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'})
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
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'})
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
                worker = Worker(self.db, None, None, '.', {123: 'acme/repo'})
                claim = worker.claim()
                self.assertTrue(worker.finish(claim[0], claim[2], status, {'status': status}))
                with patch('receiver.MAX_QUEUE', 1):
                    self.assertEqual(self.send(payload(action='synchronize'), {'X-GitHub-Delivery': 'new'}), 503)
                with closing(sqlite3.connect(self.db)) as db, db:
                    self.assertEqual(db.execute('SELECT status FROM work').fetchone()[0], status)
                    db.execute('DELETE FROM work'); db.execute('DELETE FROM queue')

    def test_insert_integrity_error_rolls_back_cleanup(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'})
        claim = worker.claim()
        self.assertTrue(worker.finish(claim[0], claim[2], 'done', {'status': 'done'}))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET completed_at=0')
            db.execute("UPDATE outbox SET status='sent'")
            before = db.execute('SELECT * FROM work').fetchall()
            db.execute("CREATE TRIGGER reject_insert BEFORE INSERT ON queue BEGIN SELECT RAISE(ABORT, 'fail'); END")
        with patch('receiver.MAX_QUEUE', 1):
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)
            with closing(sqlite3.connect(self.db)) as db, db:
                self.assertEqual(db.execute('SELECT delivery_id, body FROM queue').fetchall(), [('test-id', payload())])
                self.assertEqual(db.execute('SELECT * FROM work').fetchall(), before)
                self.assertEqual(db.execute('SELECT count(*) FROM tombstone').fetchone()[0], 0)
                db.execute('DROP TRIGGER reject_insert')
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 202)

    def test_cleanup_rollback_and_restart_preserve_replay(self):
        from worker import Worker
        from receiver import create_server
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'})
        claim = worker.claim()
        self.assertTrue(worker.finish(claim[0], claim[2], 'done', {'status': 'done'}))
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
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 202)
            server = create_server('secret', {123: 'acme/repo'}, self.db, port=0)
            server.server_close()
            self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'alias'}), 200)

    def test_full_queue_never_evicts_running_or_retry_work(self):
        from worker import Worker
        self.assertEqual(self.send(), 202)
        worker = Worker(self.db, None, None, '.', {123: 'acme/repo'})
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
