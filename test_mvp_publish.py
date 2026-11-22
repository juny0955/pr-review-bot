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
from revocation_gate import update_gate

REPO = 'juny0955/pr-review-bot'
HEAD, BASE = 'a' * 40, 'b' * 40


class MVPTests(unittest.TestCase):
    @patch('revocation_gate._trusted_directory', side_effect=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    def test_signed_approved_result_posts_once_and_rejects_tampering(self, _trusted):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as root:
            gate = os.path.join(root, 'gate')
            os.mkdir(gate, 0o700)
            open(os.path.join(gate, 'lock'), 'w').close()
            os.chmod(os.path.join(gate, 'lock'), 0o600)
            review = 'Check the boundary condition.'
            update_gate(gate, {'123': REPO}, [[123, REPO, 7, HEAD, BASE, hashlib.sha256(review.encode()).hexdigest()]])
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
                with closing(sqlite3.connect(db)) as conn, conn:
                    conn.execute('UPDATE webhook_signatures SET signature=?', ('sha256=' + '0' * 64,))
                publication_loop(db, {123: REPO}, github, auth, ledger, gate, 'test-secret', Once())
                self.assertEqual(post.call_count, 1)


if __name__ == '__main__':
    unittest.main()
