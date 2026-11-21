from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from publish_worker import publish_worker_result

REPO, HEAD, BASE = 'owner/repo', 'a' * 40, 'b' * 40
EVENT = {'repository': {'id': 1, 'full_name': REPO}, 'number': 7,
         'pull_request': {'number': 7, 'head': {'sha': HEAD}, 'state': 'open', 'draft': False},
         'action': 'opened'}
RESULT = {'status': 'done', 'repo_id': 1, 'repository': REPO, 'number': 7, 'sha': HEAD,
          'base_sha': BASE, 'review': 'exact review'}


class PublishWorkerTests(unittest.TestCase):
    def test_replaced_event_id_and_legacy_result_fail_closed(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE queue SET body=?', (json.dumps(dict(EVENT, repository={'id': 2, 'full_name': REPO})),))
            db.execute('UPDATE work SET result=?', (json.dumps(dict(RESULT, repo_id=1)),))
        with self.assertRaises(ValueError):
            self.publish(repos={2: REPO}, current=Mock(return_value=dict(self.current.return_value, repo_id=2)))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE work SET result=?', (json.dumps({k: v for k, v in RESULT.items() if k != 'repo_id'}),))
        with self.assertRaises(ValueError):
            self.publish(repos={2: REPO})
        self.post.assert_not_called()

    def test_enabled_must_fail_closed_without_revocation_gate(self):
        with self.assertRaises(ValueError):
            self.publish(enabled=True)
        self.post.assert_not_called()

    def setUp(self):
        if self._testMethodName != 'test_enabled_must_fail_closed_without_revocation_gate':
            gate = patch('publisher._require_revocation_gate')
            gate.start()
            self.addCleanup(gate.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / 'queue')
        self.ledger = str(Path(self.tmp.name) / 'ledger')
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
            db.execute('CREATE TABLE work (delivery_id TEXT PRIMARY KEY, status TEXT, result TEXT)')
            db.execute('INSERT INTO queue VALUES (?,?)', ('id', json.dumps(EVENT)))
            db.execute('INSERT INTO work VALUES (?,?,?)', ('id', 'done', json.dumps(RESULT)))
        self.post = Mock()
        self.current = Mock(return_value={'repo_id': 1, 'repo': REPO, 'state': 'open',
                                          'draft': False, 'sha': HEAD, 'base_sha': BASE})
        self.approve = Mock(return_value=True)

    def publish(self, **kw):
        options = dict(post=self.post, current=self.current, get=Mock(return_value=[]),
                       repos={1: REPO}, ledger_path=self.ledger, approve=self.approve)
        options.update(kw)
        return publish_worker_result(self.db, 'id', **options)

    def test_dry_run_and_exact_approved_result(self):
        self.assertEqual(self.publish(), 'dry_run')
        self.post.assert_not_called()
        self.assertEqual(self.publish(enabled=True), 'sent')
        self.assertEqual(self.approve.call_args.args, (1, REPO, 7, HEAD, BASE, 'exact review'))
        self.assertTrue(self.post.call_args.args[1]['body'].startswith('exact review\n\n'))
        self.assertEqual(self.publish(enabled=True), 'sent')
        self.assertEqual(self.post.call_count, 1)

    def test_fail_closed_on_unapproved_or_changed_identity(self):
        for approval in (None, Mock(return_value=False), Mock(return_value=1), Mock(side_effect=RuntimeError())):
            with self.subTest(approval=approval):
                with self.assertRaises((ValueError, RuntimeError)):
                    self.publish(enabled=True, approve=approval)
        for result in (dict(RESULT, repo_id=True), dict(RESULT, repo_id=2),
                       dict(RESULT, sha='c'*40), dict(RESULT, repository='other/repo'),
                       dict(RESULT, number=True), dict(RESULT, status='retry')):
            with self.subTest(result=result):
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute('UPDATE work SET result=?', (json.dumps(result),))
                with self.assertRaises(ValueError):
                    self.publish(enabled=True)
        self.post.assert_not_called()

    def test_stale_and_uncertain_post(self):
        self.current.return_value['base_sha'] = 'c'*40
        with self.assertRaises(ValueError):
            self.publish(enabled=True)
        self.post.assert_not_called()
        self.current.return_value['base_sha'] = BASE
        self.post.side_effect = TimeoutError()
        self.assertEqual(self.publish(enabled=True), 'ambiguous')
        self.assertEqual(self.publish(enabled=True), 'ambiguous')
        self.assertEqual(self.post.call_count, 1)

    def test_missing_or_unfinished_result(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE work SET status='running'")
        with self.assertRaises(ValueError):
            self.publish(enabled=True)
        self.post.assert_not_called()
