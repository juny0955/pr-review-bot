import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import closing
import tempfile

import unittest
from unittest.mock import Mock, patch

from orchestrator import publication_loop
from revocation_gate import update_gate, gate_snapshot, authorize, locked_gate
import multiprocessing as mp


def revoke_auto(path, started, done):
    started.set()
    with patch('revocation_gate._trusted_directory', side_effect=lambda p: os.open(p, os.O_RDONLY | os.O_DIRECTORY)):
        _, version = gate_snapshot(path)
        update_gate(path, {'123': REPO}, [], auto_repos={}, expected=version)
    done.set()

REPO = 'juny0955/pr-review-bot'
HEAD, BASE = 'a' * 40, 'b' * 40


class MVPTests(unittest.TestCase):
    @patch('revocation_gate._trusted_directory', side_effect=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    def test_auto_policy_revocation_and_scope(self, _trusted):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as gate:
            open(os.path.join(gate, 'lock'), 'w').close()
            os.chmod(os.path.join(gate, 'lock'), 0o600)
            update_gate(gate, {'123': REPO}, [], auto_repos={'123': REPO})
            identity = [123, REPO, 7, HEAD, BASE, 'c' * 64]
            with self.assertRaises(ValueError):
                with authorize(gate, identity): pass
            with authorize(gate, identity, single_vps_mvp=True): pass
            with self.assertRaises(ValueError):
                with authorize(gate, [124, REPO, *identity[2:]], single_vps_mvp=True): pass
            ctx = mp.get_context('spawn')
            started, done = ctx.Event(), ctx.Event()
            proc = ctx.Process(target=revoke_auto, args=(gate, started, done))
            try:
                with authorize(gate, identity, single_vps_mvp=True):
                    proc.start()
                    self.assertTrue(started.wait(3))
                    self.assertFalse(done.wait(.3))
                proc.join(3)
                self.assertEqual(proc.exitcode, 0)
                with self.assertRaises(ValueError):
                    with authorize(gate, identity, single_vps_mvp=True): pass
                with self.assertRaises(ValueError):
                    update_gate(gate, {'123': REPO}, [], auto_repos={'123': 'other/repo'}, expected=gate_snapshot(gate)[1])
            finally:
                if proc.pid is not None:
                    if proc.is_alive(): proc.terminate()
                    proc.join()

    def test_ambiguous_is_rechecked_in_same_process_until_sent(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as root:
            db = os.path.join(root, 'queue')
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE work (delivery_id TEXT, status TEXT)')
                conn.execute("INSERT INTO work VALUES ('delivery', 'done')")
            class Stop:
                def __init__(self): self.polls = 0
                def is_set(self): return self.polls >= 3
                def wait(self, _): self.polls += 1
            with patch('orchestrator.publish_worker_result', side_effect=['ambiguous', 'sent']) as publish:
                publication_loop(db, {}, Mock(), Mock(), '', '', '', Stop())
            self.assertEqual(publish.call_count, 2)

    @patch('revocation_gate._trusted_directory', side_effect=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    def test_auto_policy_posts_without_review_approval(self, _trusted):
        from publisher import GitHubPublisher
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as gate:
            open(os.path.join(gate, 'lock'), 'w').close()
            os.chmod(os.path.join(gate, 'lock'), 0o600)
            update_gate(gate, {'123': REPO}, [], auto_repos={'123': REPO})
            post = Mock(side_effect=TimeoutError())
            current = Mock(return_value={'repo_id': 123, 'repo': REPO, 'state': 'open', 'draft': False, 'sha': HEAD, 'base_sha': BASE})
            pub = GitHubPublisher(post, current, {123: REPO}, enabled=True, single_vps_mvp=True,
                                  gate_path=gate, ledger_path=os.path.join(gate, 'ledger'), get=lambda _: [])
            with self.assertRaises(ValueError):
                pub.publish(123, REPO, 7, HEAD, 'password=supersecret', base_sha=BASE)
            current.return_value['base_sha'] = 'c' * 40
            with self.assertRaises(ValueError): pub.publish(123, REPO, 7, HEAD, 'review', base_sha=BASE)
            current.return_value['base_sha'] = BASE
            self.assertEqual(pub.publish(123, REPO, 7, HEAD, 'review', base_sha=BASE), 'ambiguous')
            self.assertEqual(pub.publish(123, REPO, 7, HEAD, 'review', base_sha=BASE), 'ambiguous')
            post.assert_called_once()

    @patch('revocation_gate._trusted_directory', side_effect=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    def test_signed_auto_result_posts_once_and_rejects_tampering(self, _trusted):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as root:
            gate = os.path.join(root, 'gate')
            os.mkdir(gate, 0o700)
            open(os.path.join(gate, 'lock'), 'w').close()
            os.chmod(os.path.join(gate, 'lock'), 0o600)
            review = 'Check the boundary condition.'
            update_gate(gate, {'123': REPO}, [], auto_repos={'123': REPO})
            db = os.path.join(root, 'queue')
            ledger = os.path.join(root, 'ledger')
            event = {'repository': {'id': 123, 'full_name': REPO}, 'number': 7,
                     'pull_request': {'number': 7, 'head': {'sha': HEAD}, 'state': 'open', 'draft': False}, 'action': 'opened'}
            body = json.dumps(event).encode()
            result = {'status': 'done', 'repo_id': 123, 'repository': REPO, 'number': 7,
                      'sha': HEAD, 'base_sha': BASE, 'review': review}
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT, body BLOB)')
                conn.execute('CREATE TABLE work (delivery_id TEXT, status TEXT, result TEXT)')
                conn.execute('CREATE TABLE webhook_signatures (delivery_id TEXT, signature TEXT)')
                conn.execute('INSERT INTO queue VALUES (?, ?)', ('delivery', body))
                conn.execute('INSERT INTO work VALUES (?, ?, ?)', ('delivery', 'done', json.dumps(result)))
                conn.execute('INSERT INTO webhook_signatures VALUES (?, ?)', ('delivery', 'sha256=' + hmac.new(b'test-secret', body, hashlib.sha256).hexdigest()))
            github = Mock()
            github.current.return_value = {'repo_id': 123, 'repo': REPO, 'state': 'open', 'draft': False, 'sha': HEAD, 'base_sha': BASE}
            auth = Mock()
            auth.token.return_value = ('synthetic-token', 999)
            class Once:
                def __init__(self): self.stopped = False
                def is_set(self): return self.stopped
                def wait(self, _): self.stopped = True
            with patch('orchestrator.publish_transport') as post, patch('orchestrator.review_list_transport', return_value=[]):
                for _ in range(2):
                    publication_loop(db, {123: REPO}, github, auth, ledger, gate, 'test-secret', Once())
                self.assertEqual(post.call_count, 1)
                self.assertEqual(post.call_args.args[1], '/repos/' + REPO + '/pulls/7/reviews')
            class ThreePolls:
                def __init__(self): self.count = 0
                def is_set(self): return self.count >= 3
                def wait(self, _): self.count += 1
            posted = []
            def timeout_after_post(_token, _path, body):
                posted.append(body)
                raise TimeoutError()
            def list_reviews(_token, _path):
                return [{'commit_id': HEAD, 'body': posted[0]['body']}]
            with patch('orchestrator.publish_transport', side_effect=timeout_after_post) as post, \
                 patch('orchestrator.review_list_transport', side_effect=list_reviews) as get:
                publication_loop(db, {123: REPO}, github, auth, os.path.join(root, 'ledger2'), gate, 'test-secret', ThreePolls())
                self.assertEqual(post.call_count, 1)
                self.assertEqual(get.call_count, 1)
                with closing(sqlite3.connect(os.path.join(root, 'ledger2'))) as conn:
                    self.assertEqual(conn.execute("SELECT count(*) FROM publications WHERE state='sent'").fetchone()[0], 1)
            with patch('orchestrator.publish_transport') as post:
                with closing(sqlite3.connect(db)) as conn, conn:
                    conn.execute('UPDATE webhook_signatures SET signature=?', ('sha256=' + '0' * 64,))
                publication_loop(db, {123: REPO}, github, auth, ledger, gate, 'test-secret', Once())
                self.assertEqual(post.call_count, 0)


if __name__ == '__main__':
    unittest.main()
