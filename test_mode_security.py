import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from contextlib import closing, nullcontext

from worker import Worker, mode_provenance
from outbox import Outbox
from publish_worker import publish_worker_result
from retention import cleanup_done
from orchestrator import publication_loop

R, H, B = 'juny0955/pr-review-bot', 'a'*40, 'b'*40
EVENT = {'action':'opened','repository':{'id':123,'full_name':R},'number':7,'pull_request':{'number':7,'head':{'sha':H},'base':{'sha':B},'state':'open','draft':False}}
RESULT = {'status':'done','repo_id':123,'repository':R,'number':7,'sha':H,'base_sha':B,'review':'synthetic'}

class ModeSecurity(unittest.TestCase):
    def test_provenance_binds_each_input(self):
        mac = mode_provenance('fake', 'd', b'body', 1, 0)
        for args in [('fake', 'other', b'body', 1, 0), ('fake', 'd', b'other', 1, 0),
                     ('fake', 'd', b'body', 0, 0), ('fake', 'd', b'body', 1, 1),
                     ('other', 'd', b'body', 1, 0)]:
            self.assertNotEqual(mac, mode_provenance(*args))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name)/'q')
        self.ledger = str(Path(self.tmp.name)/'l')
        self.body = json.dumps(EVENT).encode()
        with closing(sqlite3.connect(self.db)) as c, c:
            c.executescript('CREATE TABLE queue(delivery_id TEXT PRIMARY KEY,body BLOB); CREATE TABLE webhook_signatures(delivery_id TEXT,signature TEXT); CREATE TABLE tombstone(delivery_id TEXT PRIMARY KEY,body_hash BLOB);')
            c.execute('INSERT INTO queue VALUES (?,?)', ('d',self.body))
            c.execute('INSERT INTO webhook_signatures VALUES (?,?)', ('d','sha256='+hmac.new(b'fake',self.body,hashlib.sha256).hexdigest()))

    def worker(self, live=False, notifications=False, now=100):
        return Worker(self.db, Mock(), Mock(), self.tmp.name, {123:R}, clock=lambda:now, lease_seconds=1, publish_eligible=live, notifications_enabled=notifications, webhook_secret='fake')

    def test_retry_and_outbox_require_valid_mode_provenance(self):
        for live, notifications in ((1, 1), (0, 1)):
            for bad in (None, '0' * 64, 'é' * 64):
                with self.subTest(live=live, bad=bad):
                    w = self.worker(bool(live), bool(notifications))
                    with closing(sqlite3.connect(self.db)) as c, c:
                        c.execute('DELETE FROM work')
                        c.execute("INSERT INTO work(delivery_id,status,attempts,next_attempt_at,publish_eligible,notifications_enabled,mode_provenance) VALUES ('d','retry',1,0,?,?,?)", (live, notifications, bad))
                    with patch('worker.wiki_evidence') as wiki:
                        self.assertIsNone(w.run_once())
                    w.github.current.assert_not_called()
                    w.model.review.assert_not_called()
                    wiki.assert_not_called()
                    send = Mock()
                    box = Outbox(self.db, clock=lambda:100, repos={123:R}, webhook_secret='fake')
                    self.assertIsNone(box.send_once(send))
                    send.assert_not_called()
                    with closing(sqlite3.connect(self.db)) as c:
                        self.assertEqual(c.execute('SELECT status,attempts,mode_provenance FROM work').fetchone(), ('retry', 1, bad))

    def test_invalid_candidate_does_not_starve_valid_retry(self):
        w = self.worker(notifications=True)
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute("INSERT INTO work(delivery_id,status,attempts,next_attempt_at,publish_eligible,notifications_enabled) VALUES ('d','retry',1,0,0,1)")
            c.execute('INSERT INTO queue VALUES (?,?)', ('e', self.body))
            c.execute("INSERT INTO work(delivery_id,status,attempts,next_attempt_at,publish_eligible,notifications_enabled,mode_provenance) VALUES ('e','retry',1,0,0,1,?)", (mode_provenance('fake', 'e', self.body, 0, 1),))
        self.assertEqual(w.claim()[0], 'e')

    def test_outbox_checks_mode_and_source_before_send(self):
        w = self.worker(notifications=True)
        w.claim()
        box = Outbox(self.db, clock=lambda:100, repos={123:R}, webhook_secret='fake')
        send = Mock()
        with closing(sqlite3.connect(self.db)) as c, c:
            original = c.execute('SELECT mode_provenance FROM work').fetchone()[0]
            c.execute("UPDATE outbox SET repo_id=123,repo_name=?,pr_number=7", (R,))
        for value in (None, '0' * 64, 'é' * 64):
            with closing(sqlite3.connect(self.db)) as c, c:
                c.execute('UPDATE work SET mode_provenance=?', (value,))
            self.assertIsNone(box.send_once(send))
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('UPDATE work SET mode_provenance=?', (original,))
            c.execute('UPDATE queue SET body=?', (b'{}',))
        self.assertIsNone(box.send_once(send))
        send.assert_not_called()
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('UPDATE queue SET body=?', (self.body,))
        self.assertEqual(box.send_once(send), 'sent')
        send.assert_called_once()

    def publish(self, secret='fake', mvp=True):
        return publish_worker_result(self.db, 'd', post=self.post, current=Mock(return_value={'repo_id':123,'repo':R,'state':'open','draft':False,'sha':H,'base_sha':B}), repos={123:R}, get=lambda _:[], ledger_path=self.ledger, enabled=True, approve=lambda *a:True, gate_path='fake', single_vps_mvp=mvp, webhook_secret=secret)

    def test_provenance_and_direct_paths(self):
        self.post = Mock()
        w = self.worker()
        _,_,token = w.claim()
        w.finish('d',token,'done',RESULT)
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('UPDATE work SET publish_eligible=1')
        for mvp in (True, False):
            with self.assertRaises(ValueError): self.publish(mvp=mvp)
        self.post.assert_not_called()

    def test_live_provenance_valid_and_tampering_rejected(self):
        self.post = Mock()
        w = self.worker(live=True)
        _, _, token = w.claim()
        w.finish('d', token, 'done', RESULT)
        with closing(sqlite3.connect(self.db)) as c, c:
            original = c.execute('SELECT mode_provenance FROM work').fetchone()[0]
        for field, value in [('mode_provenance', None), ('mode_provenance', '0'*64), ('notifications_enabled', 1)]:
            with closing(sqlite3.connect(self.db)) as c, c:
                c.execute(f'UPDATE work SET {field}=?', (value,))
            with self.assertRaises(ValueError): self.publish()
            with closing(sqlite3.connect(self.db)) as c, c:
                c.execute('UPDATE work SET mode_provenance=?,notifications_enabled=0', (original,))
        with self.assertRaises(ValueError): self.publish(secret='wrong')
        with patch('publisher._require_revocation_gate', return_value=nullcontext()):
            self.assertEqual(self.publish(), 'sent')
        self.post.assert_called_once()

    def test_poll_cannot_publish_modified_dry_mode(self):
        w = self.worker()
        _, _, token = w.claim()
        w.finish('d', token, 'done', RESULT)
        with closing(sqlite3.connect(self.db)) as c, c: c.execute('UPDATE work SET publish_eligible=1')
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        github, auth = Mock(), Mock()
        github.current.return_value = {'repo_id':123,'repo':R,'state':'open','draft':False,'sha':H,'base_sha':B}
        auth.token.return_value = ('fake', 999)
        with patch('publisher._require_revocation_gate', return_value=nullcontext()), patch('orchestrator.publish_transport') as post:
            publication_loop(self.db, {123:R}, github, auth, self.ledger, 'fake', 'fake', stop)
            post.assert_not_called()

    def test_before_claim_and_expired_suppressed(self):
        w = self.worker()
        box = Outbox(self.db, clock=lambda:1000, repos={123:R})
        sent = Mock()
        self.assertIsNone(box.send_once(sent))
        w.claim()
        with closing(sqlite3.connect(self.db)) as c, c: c.execute('UPDATE work SET attempts=3')
        self.worker(notifications=True, now=1000).claim()
        self.assertIsNone(box.send_once(sent))
        with closing(sqlite3.connect(self.db)) as c, c:
            self.assertEqual(c.execute("SELECT status FROM outbox WHERE event='failed'").fetchone(), ('suppressed',))
        sent.assert_not_called()

    def test_legacy_ambiguous_preserved(self):
        w = self.worker()
        _,_,token=w.claim()
        w.finish('d',token,'done',RESULT)
        with closing(sqlite3.connect(self.db)) as c, c: c.execute('UPDATE work SET completed_at=0')
        key = hashlib.sha256(json.dumps([123,R,7,H,'synthetic'],ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
        with closing(sqlite3.connect(self.ledger)) as c, c:
            c.execute('CREATE TABLE publications(key TEXT PRIMARY KEY,marker TEXT,state TEXT)')
            c.execute('INSERT INTO publications VALUES (?,?,?)',(key,'old','ambiguous'))
        for state in ('ambiguous', 'pending', 'sent'):
            with closing(sqlite3.connect(self.ledger)) as c, c: c.execute('UPDATE publications SET state=?', (state,))
            self.assertFalse(cleanup_done(self.db,self.ledger,'d','fake'))
