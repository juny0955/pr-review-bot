from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from github_app_transport import publish_transport
from inline_review import PREFIX, prepare_review
from publisher import GitHubPublisher
from test_publisher import ID, REPO, SHA, POLICY, fresh


class InlinePreflightTest(unittest.TestCase):
    def test_limit_and_invalid_decoded_text_before_claim(self):
        diff = 'diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+new\n'
        item = {'path': 'a.py', 'line': 1, 'body': 'fix'}
        with tempfile.TemporaryDirectory() as directory, patch('publisher._require_revocation_gate'), patch('publisher._require_operational_isolation'):
            ledger = Path(directory) / 'ledger'
            request = Mock(side_effect=lambda method, path, token, payload: {
                'id': 1, 'commit_id': payload['commit_id'], 'body': payload['body'], 'state': 'COMMENTED'})
            post = Mock(side_effect=lambda path, body: publish_transport('token', '/' + path, body))
            pub = GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True,
                                  ledger_path=ledger, get=Mock(return_value=[]), diff=Mock(return_value=diff))
            with patch('github_app_transport._request', request):
                valid = prepare_review(json.dumps({'body': 'summary', 'comments': [item] * 100}), diff)
                self.assertEqual(pub.publish(ID, REPO, 7, SHA, valid, base_sha='b' * 40), 'sent')
                self.assertEqual(len(request.call_args.args[3]['comments']), 100)
                post.reset_mock()
                request.reset_mock()
                with closing(sqlite3.connect(ledger)) as db:
                    before = db.execute('SELECT COUNT(*) FROM publications').fetchone()[0]
                raw_comment = {**item, 'side': 'RIGHT'}
                bad_reviews = [
                    prepare_review(json.dumps({'body': 'summary', 'comments': [item] * 101}), diff),
                    PREFIX + json.dumps({'body': 'summary', 'comments': [raw_comment] * 101}),
                    PREFIX + json.dumps({'body': 'summary', 'comments': [{**raw_comment, 'body': '\ud800'}]}),
                    PREFIX + json.dumps({'body': '\ud800', 'comments': []}),
                ]
                for review in bad_reviews:
                    with self.subTest(review=review[:60]), self.assertRaises(ValueError):
                        pub.publish(ID, REPO, 7, SHA, review, base_sha='b' * 40)
                post.assert_not_called()
                request.assert_not_called()
                with closing(sqlite3.connect(ledger)) as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM publications').fetchone()[0], before)


if __name__ == '__main__':
    unittest.main()
