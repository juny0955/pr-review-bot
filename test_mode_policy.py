import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

from orchestrator import publication_loop
from retention import cleanup_done
from worker import Worker, mode_provenance, result_provenance
from test_worker import sign_queue


class ModePolicyTest(unittest.TestCase):
    def test_claim_binds_mode_and_retry_cannot_change_it(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / 'queue')
            with closing(sqlite3.connect(db)) as c, c:
                c.execute('CREATE TABLE queue(delivery_id TEXT PRIMARY KEY, body BLOB)')
                c.execute("INSERT INTO queue VALUES('id', X'7b7d')")
                sign_queue(c, 'id', 'fake')
            dry = Worker(db, Mock(), Mock(), d, {1: 'a/b'}, clock=lambda: 100, publish_eligible=False, notifications_enabled=False, webhook_secret='fake')
            delivery, _, token = dry.claim()
            dry.finish(delivery, token, 'retry', {'status': 'retry'})
            live = Worker(db, Mock(), Mock(), d, {1: 'a/b'}, clock=lambda: 1000, publish_eligible=True, notifications_enabled=True, webhook_secret='fake')
            self.assertIsNone(live.claim())
            dry.clock = lambda: 1000
            self.assertIsNotNone(dry.claim())
            with closing(sqlite3.connect(db)) as c:
                self.assertEqual(c.execute('SELECT publish_eligible,notifications_enabled FROM work').fetchone(), (0, 0))
                self.assertEqual(set(x[0] for x in c.execute('SELECT status FROM outbox')), {'suppressed'})

    def test_publication_poll_only_explicit_live(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / 'queue')
            with closing(sqlite3.connect(db)) as c, c:
                c.execute('CREATE TABLE work(delivery_id TEXT, status TEXT, publish_eligible INTEGER)')
                c.executemany('INSERT INTO work VALUES (?,\'done\',?)', [('live', 1), ('dry', 0), ('legacy', None)])
            stop = Mock()
            stop.is_set.side_effect = [False, False, True]
            with patch('orchestrator.publish_worker_result', return_value='sent') as publish:
                publication_loop(db, {}, Mock(), Mock(), '', '', 'fake', stop)
            self.assertEqual([call.args[1] for call in publish.call_args_list], ['live'])

    def test_dry_suppressed_cleanup_and_ambiguous_preservation(self):
        with tempfile.TemporaryDirectory() as d:
            queue, ledger = str(Path(d) / 'q'), str(Path(d) / 'l')
            event = {'repository': {'id': 1, 'full_name': 'a/b'}, 'number': 2, 'pull_request': {'number': 2, 'head': {'sha': 'a'*40}, 'base': {'sha': 'b'*40}}}
            result = {'status': 'done', 'repo_id': 1, 'repository': 'a/b', 'number': 2, 'sha': 'a'*40, 'base_sha': 'b'*40, 'review': '리뷰'}
            body = json.dumps(event).encode()
            key = hashlib.sha256(json.dumps(['v2', 1, 'a/b', 2, 'a'*40, 'b'*40, '리뷰'], ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
            with closing(sqlite3.connect(queue)) as c, c:
                c.executescript('CREATE TABLE queue(delivery_id TEXT PRIMARY KEY,body BLOB); CREATE TABLE work(delivery_id TEXT PRIMARY KEY,status TEXT,completed_at REAL,result TEXT,publish_eligible INTEGER,notifications_enabled INTEGER,mode_provenance TEXT); CREATE TABLE outbox(delivery_id TEXT,event TEXT,status TEXT,repo_id INTEGER,repo_name TEXT,pr_number INTEGER); CREATE TABLE webhook_signatures(delivery_id TEXT,signature TEXT); CREATE TABLE tombstone(delivery_id TEXT PRIMARY KEY,body_hash BLOB);')
                c.execute('INSERT INTO queue VALUES (?,?)', ('id', body))
                c.execute('INSERT INTO work VALUES (?,?,?,?,?,?,?)', ('id','done',0,json.dumps(result),0,0,mode_provenance('secret','id',body,0,0)))
                c.execute('ALTER TABLE work ADD COLUMN result_provenance TEXT')
                c.execute('UPDATE work SET result_provenance=?', (result_provenance('secret','id',body,0,0,json.dumps(result)),))
                c.execute('INSERT INTO webhook_signatures VALUES (?,?)', ('id','sha256='+hmac.new(b'secret',body,hashlib.sha256).hexdigest()))
                c.executemany('INSERT INTO outbox VALUES (?,?,?,?,?,?)', [('id', x, 'suppressed', None, None, None) for x in ('detected','started','completed')])
            with closing(sqlite3.connect(ledger)) as c, c:
                c.execute('CREATE TABLE publications(key TEXT PRIMARY KEY,state TEXT)')
                c.execute('INSERT INTO publications VALUES (?,?)', (key, 'pending'))
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'))
            with closing(sqlite3.connect(ledger)) as c, c:
                c.execute('DELETE FROM publications')
            with closing(sqlite3.connect(queue)) as c, c:
                c.execute("UPDATE outbox SET status='pending' WHERE event='started'")
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'))
            with closing(sqlite3.connect(queue)) as c, c:
                c.execute("UPDATE outbox SET status='suppressed' WHERE event='started'")
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'wrong'))
            for mode in ((None, None), (1, 0), (0, None), (2, 0), (0, 1)):
                with closing(sqlite3.connect(queue)) as c, c:
                    c.execute('UPDATE work SET publish_eligible=?,notifications_enabled=?', mode)
                self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'), mode)
            with closing(sqlite3.connect(queue)) as c, c:
                c.execute('UPDATE work SET publish_eligible=0,notifications_enabled=0')
                c.execute("UPDATE work SET completed_at=CAST(strftime('%s','now') AS INTEGER)")
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'))
            with closing(sqlite3.connect(queue)) as c, c:
                c.execute('UPDATE work SET completed_at=0')
            self.assertTrue(cleanup_done(queue, ledger, 'id', 'secret'))
