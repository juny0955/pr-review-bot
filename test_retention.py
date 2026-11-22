from contextlib import closing
import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from retention import cleanup_done
from worker import mode_provenance


class RetentionTest(unittest.TestCase):
    def test_cleanup_requires_authentic_modes(self):
        with tempfile.TemporaryDirectory() as d:
            queue, ledger = str(Path(d) / 'q'), str(Path(d) / 'l')
            event = {'repository': {'id': 1, 'full_name': 'a/b'}, 'number': 2,
                     'pull_request': {'number': 2, 'head': {'sha': 'a'*40}, 'base': {'sha': 'b'*40}}}
            result = {'status': 'done', 'repo_id': 1, 'repository': 'a/b', 'number': 2,
                      'sha': 'a'*40, 'base_sha': 'b'*40, 'review': 'review'}
            body = json.dumps(event).encode()
            with closing(sqlite3.connect(queue)) as db, db:
                db.executescript('CREATE TABLE queue(delivery_id TEXT PRIMARY KEY,body BLOB); CREATE TABLE work(delivery_id TEXT PRIMARY KEY,status TEXT,completed_at REAL,result TEXT,publish_eligible INTEGER,notifications_enabled INTEGER,mode_provenance TEXT); CREATE TABLE outbox(delivery_id TEXT,event TEXT,status TEXT,repo_id INTEGER,repo_name TEXT,pr_number INTEGER); CREATE TABLE webhook_signatures(delivery_id TEXT,signature TEXT); CREATE TABLE tombstone(delivery_id TEXT PRIMARY KEY,body_hash BLOB);')
                db.execute('INSERT INTO queue VALUES (?,?)', ('id', body))
                db.execute('INSERT INTO work VALUES (?,?,?,?,?,?,?)', ('id', 'done', 0, json.dumps(result), 0, 0, mode_provenance('secret', 'id', body, 1, 0)))
                db.execute('INSERT INTO webhook_signatures VALUES (?,?)', ('id', 'sha256=' + hmac.new(b'secret', body, hashlib.sha256).hexdigest()))
                db.executemany('INSERT INTO outbox VALUES (?,?,?,?,?,?)', [('id', name, 'suppressed', None, None, None) for name in ('detected', 'started', 'completed')])
            with closing(sqlite3.connect(ledger)) as db, db:
                db.execute('CREATE TABLE publications(key TEXT PRIMARY KEY,marker TEXT,state TEXT)')
            for provenance in (mode_provenance('secret', 'id', body, 1, 0), None, '0'*64, 'é'*64):
                with closing(sqlite3.connect(queue)) as db, db:
                    db.execute('UPDATE work SET mode_provenance=?', (provenance,))
                self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'))
                with closing(sqlite3.connect(queue)) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 1)
                    self.assertEqual(db.execute('SELECT count(*) FROM tombstone').fetchone()[0], 0)
            with closing(sqlite3.connect(queue)) as db, db:
                db.execute('UPDATE work SET publish_eligible=NULL,notifications_enabled=NULL,mode_provenance=NULL')
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'))
            with closing(sqlite3.connect(queue)) as db, db:
                db.execute('UPDATE work SET publish_eligible=0,notifications_enabled=0')
                db.execute('UPDATE work SET mode_provenance=?', (mode_provenance('secret', 'id', body, 0, 0),))
            self.assertTrue(cleanup_done(queue, ledger, 'id', 'secret'))

    def test_only_verified_old_sent_result_is_removed(self):
        with tempfile.TemporaryDirectory() as d:
            queue, ledger = str(Path(d) / 'queue'), str(Path(d) / 'ledger')
            event = {'repository': {'id': 1, 'full_name': 'a/b'}, 'number': 2,
                     'pull_request': {'number': 2, 'head': {'sha': 'a' * 40}, 'base': {'sha': 'b' * 40}}}
            result = {'status': 'done', 'repo_id': 1, 'repository': 'a/b', 'number': 2,
                      'sha': 'a' * 40, 'base_sha': 'b' * 40, 'review': 'review'}
            body = json.dumps(event).encode()
            key = hashlib.sha256(json.dumps(['v2', 1, 'a/b', 2, 'a' * 40, 'b' * 40, 'review'], ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
            with closing(sqlite3.connect(queue)) as db, db:
                db.executescript('CREATE TABLE queue(delivery_id TEXT PRIMARY KEY, body BLOB); CREATE TABLE work(delivery_id TEXT PRIMARY KEY, status TEXT, completed_at REAL, result TEXT); CREATE TABLE outbox(delivery_id TEXT, event TEXT, status TEXT, repo_id INTEGER, repo_name TEXT, pr_number INTEGER); CREATE TABLE webhook_signatures(delivery_id TEXT, signature TEXT); CREATE TABLE tombstone(delivery_id TEXT PRIMARY KEY, body_hash BLOB);')
                db.execute('INSERT INTO queue VALUES (?,?)', ('id', body))
                db.execute('INSERT INTO work VALUES (?,?,?,?)', ('id', 'done', 0, json.dumps(result)))
                db.execute('ALTER TABLE work ADD COLUMN publish_eligible INTEGER')
                db.execute('ALTER TABLE work ADD COLUMN notifications_enabled INTEGER')
                db.execute('ALTER TABLE work ADD COLUMN mode_provenance TEXT')
                db.execute('UPDATE work SET publish_eligible=1, notifications_enabled=1, mode_provenance=?', (mode_provenance('secret', 'id', body, 1, 1),))
                db.execute('INSERT INTO webhook_signatures VALUES (?,?)', ('id', 'sha256=' + hmac.new(b'secret', body, hashlib.sha256).hexdigest()))
                db.executemany('INSERT INTO outbox VALUES (?,?,?,?,?,?)',
                               [('id', name, 'sent', 1, 'a/b', 2) for name in ('detected', 'started', 'completed')])
            with closing(sqlite3.connect(ledger)) as db, db:
                db.execute('CREATE TABLE publications(key TEXT PRIMARY KEY, marker TEXT, state TEXT)')
                db.execute('INSERT INTO publications VALUES (?,?,?)', (key, 'marker', 'pending'))
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'))
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'wrong-secret'))
            with closing(sqlite3.connect(ledger)) as db, db:
                db.execute("UPDATE publications SET state='sent' WHERE key=?", (key,))
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'wrong-secret'))
            with closing(sqlite3.connect(queue)) as db, db:
                db.execute("UPDATE work SET completed_at=CAST(strftime('%s','now') AS INTEGER) WHERE delivery_id='id'")
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'))
            with closing(sqlite3.connect(queue)) as db, db:
                db.execute("UPDATE work SET completed_at=0 WHERE delivery_id='id'")
            with closing(sqlite3.connect(queue)) as db, db:
                db.execute("UPDATE outbox SET status='failed' WHERE delivery_id='id'")
            self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'))
            with closing(sqlite3.connect(queue)) as db, db:
                db.execute("UPDATE outbox SET status='sent' WHERE delivery_id='id'")
            for field, bad in [('repo_id', 99), ('repository', 'x/y'), ('number', 3),
                               ('sha', 'c' * 40), ('base_sha', 'c' * 40)]:
                for value in (bad, None):
                    altered = dict(result)
                    if value is None:
                        del altered[field]
                    else:
                        altered[field] = value
                    with closing(sqlite3.connect(queue)) as db, db:
                        db.execute('UPDATE work SET result=?', (json.dumps(altered),))
                    self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'), (field, value))
            with closing(sqlite3.connect(queue)) as db, db:
                db.execute('UPDATE work SET result=?', (json.dumps(result),))
            for name in ('detected', 'started', 'completed'):
                with closing(sqlite3.connect(queue)) as db, db:
                    db.execute('DELETE FROM outbox WHERE event=?', (name,))
                self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'), name)
                with closing(sqlite3.connect(queue)) as db, db:
                    db.execute('INSERT INTO outbox VALUES (?,?,?,?,?,?)', ('id', name, 'sent', 1, 'a/b', 2))
            for column, bad in [('repo_id', 99), ('repo_name', 'x/y'), ('pr_number', 3)]:
                for value in (bad, None):
                    with closing(sqlite3.connect(queue)) as db, db:
                        db.execute(f'UPDATE outbox SET {column}=? WHERE event=\'started\'', (value,))
                    self.assertFalse(cleanup_done(queue, ledger, 'id', 'secret'), (column, value))
                with closing(sqlite3.connect(queue)) as db, db:
                    db.execute("UPDATE outbox SET repo_id=1,repo_name='a/b',pr_number=2")
            with closing(sqlite3.connect(queue)) as db, db:
                self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT count(*) FROM work').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT count(*) FROM tombstone').fetchone()[0], 0)
            self.assertTrue(cleanup_done(queue, ledger, 'id', 'secret'))
            with closing(sqlite3.connect(queue)) as db, db:
                self.assertEqual(db.execute('SELECT * FROM tombstone').fetchone(), ('id', hashlib.sha256(body).digest()))
                for table in ('queue', 'work', 'webhook_signatures'):
                    self.assertEqual(db.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0], 3)
            with closing(sqlite3.connect(ledger)) as db, db:
                self.assertEqual(db.execute('SELECT state FROM publications WHERE key=?', (key,)).fetchone(), ('sent',))


if __name__ == '__main__':
    unittest.main()
