from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from test_worker import FakeGH, FakeModel, payload
from worker import Worker


class OutboxTest(unittest.TestCase):
    def test_policy_is_rechecked_and_recovers_without_spending_attempts(self):
        from outbox import Outbox
        with tempfile.TemporaryDirectory() as directory:
            db, policy = Path(directory) / 'queue', Path(directory) / 'repos.json'
            now, sent = [0], []
            def set_policy(entries):
                policy.write_text(json.dumps({'repositories': entries}))
            entry = {'id': 123, 'full_name': 'example-owner/example-repo', 'enabled': True}
            set_policy([entry])
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
            box = Outbox(db, repos=policy, clock=lambda: now[0])
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('INSERT INTO queue VALUES (?,?)', ('one', json.dumps(payload())))
                conn.execute("UPDATE outbox SET repo_id=123,repo_name='example-owner/example-repo',pr_number=1")
            for entries in ([], [dict(entry, enabled=False)], None):
                if entries is None:
                    policy.unlink()
                else:
                    set_policy(entries)
                self.assertEqual(box.send_once(sent.append), 'held')
                now[0] += 30
            set_policy([entry])
            self.assertEqual(box.send_once(sent.append), 'sent')
            self.assertEqual(len(sent), 1)
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute('SELECT attempts FROM outbox').fetchone()[0], 1)

    def test_partial_legacy_identity_is_revalidated_on_retry_without_overwrite(self):
        from outbox import Outbox
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            policy, now, sent = {}, [0], []
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
                conn.execute("CREATE TABLE outbox (id INTEGER PRIMARY KEY, delivery_id TEXT NOT NULL, event TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0, lease_token TEXT, lease_until REAL, repo_id INTEGER, UNIQUE(delivery_id,event,attempt))")
                conn.execute('INSERT INTO queue VALUES (?,?)', ('one', json.dumps(payload())))
                conn.execute("INSERT INTO outbox(delivery_id,event,repo_id,status) VALUES ('one','started',123,'failed')")
                conn.execute("INSERT INTO outbox(delivery_id,event,repo_id) VALUES ('one','completed',456)")
                conn.execute("INSERT INTO outbox(delivery_id,event,repo_id) VALUES ('missing','detected',123)")
            box = Outbox(db, repos=policy, clock=lambda: now[0])
            self.assertEqual(box.send_once(sent.append), 'held')
            policy[123] = 'example-owner/example-repo'
            now[0] += 30
            # Conflicting and missing source identities stay held, never overwritten.
            for _ in range(4):
                box.send_once(sent.append)
            self.assertTrue(any('example-owner/example-repo #1' in item for item in sent))
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(conn.execute("SELECT repo_id,repo_name,pr_number FROM outbox WHERE event='completed'").fetchone(), (456, None, None))
                self.assertEqual(conn.execute("SELECT status FROM outbox WHERE delivery_id='missing'").fetchone()[0], 'pending')

    def test_signed_webhook_through_worker_and_fake_discord(self):
        import hashlib
        import hmac
        import http.client
        import threading
        from notification import DiscordNotifier
        from orchestrator import deliver_notification
        from outbox import Outbox
        from receiver import create_server
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            policy = {123: 'example-owner/example-repo'}
            server = create_server('secret', policy, db, port=0)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                body = json.dumps(payload()).encode()
                headers = {'X-Hub-Signature-256': 'sha256=' + hmac.new(b'secret', body, hashlib.sha256).hexdigest(),
                           'X-GitHub-Event': 'pull_request', 'X-GitHub-Delivery': 'one'}
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                conn.request('POST', '/webhook', body, headers)
                response = conn.getresponse()
                self.assertEqual(response.status, 202)
                response.read()
                conn.close()
                worker = Worker(db, FakeGH(), FakeModel(), directory, policy)
                self.assertEqual(worker.run_once()['status'], 'done')
                with closing(sqlite3.connect(db)) as conn, conn:
                    conn.execute('DELETE FROM work')
                    conn.execute('DELETE FROM queue')
                sent = []
                notifier = DiscordNotifier(['123'], lambda channel, body: sent.append(body), enabled=True)
                box = Outbox(db, repos=policy)
                for _ in range(3):
                    self.assertEqual(box.send_once(lambda message: deliver_notification(notifier, '123', message)), 'sent')
                self.assertEqual([item['content'] for item in sent], [message + ' `example-owner/example-repo #1` (repository ID 123)' for message in ['PR detected.', 'PR review started.', 'PR review completed.']])
                self.assertTrue(all(item['allowed_mentions'] == {'parse': []} for item in sent))
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_identity_survives_deletion_and_corruption_fails_closed(self):
        from outbox import Outbox
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
            box = Outbox(db, repos={123: 'example-owner/example-repo'})
            with closing(sqlite3.connect(db)) as conn, conn:
                for n in (1, 2):
                    data = payload(); data['number'] = data['pull_request']['number'] = n
                    data['pull_request']['title'] = 'SECRET TITLE'
                    conn.execute('INSERT INTO queue VALUES (?,?)', (str(n), json.dumps(data)))
                    conn.execute('UPDATE outbox SET repo_id=123, repo_name=?, pr_number=? WHERE delivery_id=?', ('example-owner/example-repo', n, str(n)))
                conn.execute('DELETE FROM queue')
            sent = []
            self.assertEqual(box.send_once(sent.append), 'sent')
            self.assertEqual(box.send_once(sent.append), 'sent')
            self.assertIn('example-owner/example-repo #1', sent[0])
            self.assertIn('example-owner/example-repo #2', sent[1])
            self.assertNotIn('SECRET', str(sent))
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute("UPDATE outbox SET status='pending', repo_name='@everyone' WHERE id=1")
            self.assertEqual(box.send_once(sent.append), 'failed')
            self.assertEqual(len(sent), 2)

    def test_legacy_backfill_and_missing_identity(self):
        from outbox import Outbox
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
                conn.execute("CREATE TABLE outbox (id INTEGER PRIMARY KEY, delivery_id TEXT NOT NULL, event TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0, lease_token TEXT, lease_until REAL, UNIQUE(delivery_id,event,attempt))")
                conn.execute('INSERT INTO queue VALUES (?,?)', ('valid', json.dumps(payload())))
                conn.executemany('INSERT INTO outbox(delivery_id,event) VALUES (?,?)', [('valid','started'), ('missing','detected')])
            box = Outbox(db, repos={123: 'example-owner/example-repo'})
            sent = []
            self.assertEqual(box.send_once(sent.append), 'sent')
            self.assertEqual(box.send_once(sent.append), 'held')
            self.assertIn('example-owner/example-repo #1', sent[0])

    def test_untrusted_legacy_and_bad_identity_fail_closed(self):
        from outbox import Outbox
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
                data = payload(); data['repository']['full_name'] = 'other/repo'
                conn.execute('INSERT INTO queue VALUES (?,?)', ('bad', json.dumps(data)))
            box = Outbox(db, repos={123: 'example-owner/example-repo'})
            sent = []
            self.assertEqual(box.send_once(sent.append), 'held')
            with closing(sqlite3.connect(db)) as conn, conn:
                for name in ('x/' + 'a' * 201, 'x/@everyone', 'x/hello\nworld'):
                    conn.execute("INSERT INTO outbox(delivery_id,event,repo_id,repo_name,pr_number) VALUES (?, 'detected', 123, ?, 1)", (name, name))
            for _ in range(3):
                self.assertEqual(box.send_once(sent.append), 'failed')
            self.assertEqual(sent, [])

    def test_queue_and_outbox_rollback_together(self):
        from outbox import Outbox
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
            Outbox(db)
            with closing(sqlite3.connect(db)) as conn:
                conn.execute('INSERT INTO queue VALUES (?,?)', ('one', '{}'))
                conn.rollback()
                self.assertEqual(conn.execute('SELECT count(*) FROM outbox').fetchone()[0], 0)

    def test_notification_loop_drains_outbox_without_leaking_errors(self):
        from unittest.mock import Mock
        from orchestrator import notification_loop
        box, notifier, stop = Mock(), Mock(), Mock()
        stop.is_set.side_effect = [False, False, True]
        box.send_once.side_effect = ['sent', None]
        notification_loop(box, notifier, '123', stop, poll_interval=2)
        self.assertEqual(box.send_once.call_count, 2)
        stop.wait.assert_called_once_with(2)

    def test_disabled_notifier_cannot_acknowledge_delivery(self):
        from notification import DiscordNotifier
        from orchestrator import deliver_notification
        notifier = DiscordNotifier(['123'], lambda *args: None)
        with self.assertRaises(ValueError):
            deliver_notification(notifier, '123', 'PR detected.')

    def test_worker_events_and_durable_retry(self):
        from outbox import Outbox
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / 'queue'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
            now = [1000]
            outbox = Outbox(db, clock=lambda: now[0], repos={123: 'example-owner/example-repo'})
            worker = Worker(db, FakeGH(), FakeModel(), root, {123: 'example-owner/example-repo'}, clock=lambda: now[0])
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('INSERT INTO queue VALUES (?, ?)', ('one', json.dumps(payload()).encode()))
                conn.execute("UPDATE outbox SET repo_id=123,repo_name='example-owner/example-repo',pr_number=1 WHERE delivery_id='one'")
            self.assertEqual(worker.run_once()['status'], 'done')
            with closing(sqlite3.connect(db)) as conn, conn:
                self.assertEqual([r[0] for r in conn.execute('SELECT event FROM outbox ORDER BY id')], ['detected', 'started', 'completed'])
            messages = []
            def fail(message):
                raise RuntimeError('SECRET')
            self.assertEqual(outbox.send_once(fail), 'retry')
            self.assertEqual(outbox.send_once(messages.append), 'sent')
            self.assertEqual(outbox.send_once(messages.append), 'sent')
            self.assertIsNone(outbox.send_once(messages.append))
            now[0] += 30
            self.assertEqual(Outbox(db, clock=lambda: now[0], repos={123: 'example-owner/example-repo'}).send_once(messages.append), 'sent')
            with closing(sqlite3.connect(db)) as conn, conn:
                self.assertNotIn('SECRET', str(conn.execute('SELECT * FROM outbox').fetchall()))
                self.assertEqual(conn.execute("SELECT count(*) FROM outbox WHERE status='sent'").fetchone()[0], 3)

    def test_failure_and_crash_recovery_are_bounded(self):
        from outbox import Outbox
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
            now = [0]
            outbox = Outbox(db, clock=lambda: now[0], lease_seconds=10)
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('INSERT INTO queue VALUES (?, ?)', ('one', b'{}'))
            for _ in range(3):
                self.assertIsNotNone(outbox.claim())
                now[0] += 100
            self.assertIsNone(outbox.claim())
            with closing(sqlite3.connect(db)) as conn, conn:
                self.assertEqual(conn.execute('SELECT status, attempts FROM outbox').fetchone(), ('failed', 3))

    def test_terminal_work_failure_is_recorded_without_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / 'queue'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
                conn.execute('INSERT INTO queue VALUES (?, ?)', ('one', json.dumps(payload()).encode()))
            now = [1000]
            class Broken:
                def current(self, *args):
                    raise ValueError('private secret')
            worker = Worker(db, Broken(), FakeModel(), root, {123: 'example-owner/example-repo'}, clock=lambda: now[0])
            for _ in range(3):
                result = worker.run_once()
                now[0] += 100
            self.assertEqual(result['status'], 'failed')
            with closing(sqlite3.connect(db)) as conn, conn:
                events = conn.execute('SELECT event FROM outbox ORDER BY id').fetchall()
                self.assertEqual(events, [('detected',), ('started',), ('started',), ('started',), ('failed',)])
                self.assertNotIn('private secret', str(conn.execute('SELECT * FROM work').fetchall()))


if __name__ == '__main__':
    unittest.main()
