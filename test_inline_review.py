import json
import unittest
import tempfile
from contextlib import nullcontext
from unittest.mock import Mock, patch
from inline_review import prepare_review, unpack_review
from publisher import GitHubPublisher

DIFF = '''diff --git a/src/a.py b/src/a.py
index 1234567..7654321 100644
--- a/src/a.py
+++ b/src/a.py
@@ -1,2 +1,3 @@
 old
-removed
+added
+more
'''

class InlineReviewTest(unittest.TestCase):
    def test_multiline_end_to_end_and_diff_revalidation(self):
        from github_app_transport import publish_transport
        item = {'path': 'src/a.py', 'start_line': 2, 'line': 3, 'body': '오류'}
        review = prepare_review(json.dumps({'body': '요약', 'comments': [item]}), DIFF)
        expected = {**item, 'start_side': 'RIGHT', 'side': 'RIGHT'}
        self.assertEqual(unpack_review(review)[1], [expected])
        repo, ident, sha, base = 'juny0955/pr-review-bot', 1466550689, 'a' * 40, 'b' * 40
        state = {'repo_id': ident, 'repo': repo, 'state': 'open', 'draft': False, 'sha': sha, 'base_sha': base}
        request = Mock(side_effect=lambda method, path, token, payload: {
            'id': 1, 'commit_id': payload['commit_id'], 'body': payload['body'], 'state': 'COMMENTED'})
        post = Mock(side_effect=lambda path, payload: publish_transport('token', '/' + path, payload))
        with tempfile.TemporaryDirectory() as d, patch('publisher._require_revocation_gate', return_value=nullcontext()), patch('github_app_transport._request', request):
            pub = GitHubPublisher(post, Mock(return_value=state), {ident: repo}, enabled=True,
                                  single_vps_mvp=True, ledger_path=d + '/ledger', get=Mock(return_value=[]), diff=Mock(return_value=DIFF))
            self.assertEqual(pub.publish(ident, repo, 1, sha, review, base_sha=base), 'sent')
            self.assertEqual(request.call_args.args[3]['comments'], [expected])
            pub.ledger_path = d + '/other'
            pub.diff = Mock(return_value=DIFF.replace('+added', ' added').replace('@@ -1,2 +1,3 @@', '@@ -1,3 +1,3 @@'))
            self.assertEqual(pub.publish(ident, repo, 1, sha, review, base_sha=base), 'sent')
            self.assertNotIn('comments', request.call_args.args[3])
            self.assertIn('오류', request.call_args.args[3]['body'])

    def test_multiline_rejects_invalid_ranges_and_sides(self):
        from github_app_transport import publish_transport
        from inline_review import PREFIX
        diff = ('diff --git a/a b/a\n--- a/a\n+++ b/a\n'
                '@@ -1,1 +1,3 @@\n+one\n context\n+three\n'
                '@@ -5,0 +7,1 @@\n+seven\n')
        for start, end in [(1, 3), (3, 7), (3, 3), (3, 1), (0, 3), (True, 3), (1, 10**20)]:
            with self.subTest(start=start, end=end):
                item = {'path': 'a', 'start_line': start, 'line': end, 'body': 'finding'}
                body, comments = unpack_review(prepare_review(json.dumps({'body': 'summary', 'comments': [item]}), diff))
                self.assertEqual(comments, [])
                self.assertIn('finding', body)
        good = {'path': 'a', 'start_line': 1, 'start_side': 'RIGHT', 'line': 3, 'side': 'RIGHT', 'body': 'finding'}
        for change in ({'start_side': 'LEFT'}, {'side': 'LEFT'}, {'start_line': True}, {'start_line': 3}):
            comment = {**good, **change}
            encoded = PREFIX + json.dumps({'body': 'summary', 'comments': [comment]})
            self.assertEqual(unpack_review(encoded), (encoded, []))
            with patch('github_app_transport._request') as request, self.assertRaises(RuntimeError):
                publish_transport('token', '/repos/o/r/pulls/1/reviews',
                                  {'commit_id': 'a' * 40, 'event': 'COMMENT', 'body': 'summary', 'comments': [comment]})
            request.assert_not_called()

    def test_changed_lines_and_fallback(self):
        text = json.dumps({'body': '요약', 'comments': [
            {'path': 'src/a.py', 'line': 2, 'body': '오류'},
            {'path': '../secret', 'line': 2, 'body': '확인'},
            {'path': 'src/a.py', 'line': 1, 'body': '문맥'},
            {'path': 'src/a.py', 'line': 99, 'body': '누락'}]})
        body, comments = unpack_review(prepare_review(text, DIFF))
        self.assertEqual(comments, [{'path': 'src/a.py', 'line': 2, 'side': 'RIGHT', 'body': '오류'}])
        self.assertIn('확인', body)
        self.assertIn('문맥', body)
        self.assertNotIn('../secret', body)

    def test_truncated_binary_and_bad_json(self):
        text = json.dumps({'body': '요약', 'comments': [{'path': 'src/a.py', 'line': 2, 'body': '오류'}]})
        self.assertEqual(unpack_review(prepare_review(text, DIFF.rsplit('+more', 1)[0]))[1], [])
        self.assertEqual(unpack_review(prepare_review(text, 'diff --git a/src/a.py b/src/a.py\nBinary files differ\n'))[1], [])
        with self.assertRaises(ValueError):
            prepare_review('{"path":"secret', DIFF)

    def test_qa_formats_and_zero_line(self):
        from inline_review import changed_lines
        text = json.dumps({'body': '요약', 'comments': [{'path': 'src/a.py', 'line': 2, 'body': '오류'}]})
        for fenced in ('```json\n' + text + '\n```', '```\n' + text + '\n```'):
            self.assertEqual(unpack_review(prepare_review(fenced, DIFF))[1][0]['body'], '오류')
        for bad in ('{"body":"중요', '```json\n{"body":"중요', '{"body":1,"comments":[]}'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                prepare_review(bad, DIFF)
        for legacy in ('pr-review-inline-v1: 일반 리뷰', 'pr-review-inline-v1:{"body":"legacy"}',
                       'pr-review-inline-v1:{"body":"a","body":"b","comments":[]}'):
            self.assertEqual(unpack_review(legacy), (legacy, []))
        zero = 'diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +0,1 @@\n+bad\n'
        self.assertNotIn(('a', 0), changed_lines(zero))

    def test_slack_tokens_blocked_in_legacy_and_inline(self):
        from publisher import SECRET
        # Synthetic fixtures: never use real credentials.
        for token in (''.join(('xox', kind, '-', 'synthetic' * 3)) for kind in ('b', 'p')):
            self.assertIsNotNone(SECRET.search(token))
            repo, ident, sha, base = 'juny0955/pr-review-bot', 1466550689, 'a' * 40, 'b' * 40
            post = Mock()
            pub = GitHubPublisher(post, Mock(), {ident: repo}, enabled=True, single_vps_mvp=True)
            for review in ('pr-review-inline-v1: ' + token, prepare_review(json.dumps({'body': 'ok', 'comments': [{'path': 'src/a.py', 'line': 2, 'body': token}]}), DIFF)):
                with self.assertRaisesRegex(ValueError, 'potential secret'):
                    pub.publish(ident, repo, 1, sha, review, base_sha=base)
            post.assert_not_called()

    def test_legacy(self):
        self.assertEqual(unpack_review('기존 리뷰'), ('기존 리뷰', []))

    def test_publish_validated_commit_and_ledger(self):
        repo, ident, sha, base = 'juny0955/pr-review-bot', 1466550689, 'a' * 40, 'b' * 40
        review = prepare_review(json.dumps({'body': '요약', 'comments': [
            {'path': 'src/a.py', 'line': 2, 'body': '오류'}]}), DIFF)
        state = {'repo_id': ident, 'repo': repo, 'state': 'open', 'draft': False, 'sha': sha, 'base_sha': base}
        post = Mock()
        with tempfile.TemporaryDirectory() as d, patch('publisher._require_revocation_gate', return_value=nullcontext()):
            pub = GitHubPublisher(post, Mock(return_value=state), {ident: repo}, enabled=True,
                                  single_vps_mvp=True, ledger_path=d + '/ledger', get=Mock(return_value=[]), diff=Mock(return_value=DIFF))
            self.assertEqual(pub.publish(ident, repo, 1, sha, review, base_sha=base), 'sent')
            self.assertEqual(pub.publish(ident, repo, 1, sha, review, base_sha=base), 'sent')
            post.assert_called_once()
            payload = post.call_args.args[1]
            self.assertEqual(payload['commit_id'], sha)
            self.assertEqual(payload['comments'], [{'path': 'src/a.py', 'line': 2, 'side': 'RIGHT', 'body': '오류'}])
            pub.diff = Mock(side_effect=ValueError())
            pub.ledger_path = d + '/other'
            self.assertEqual(pub.publish(ident, repo, 1, sha, review, base_sha=base), 'sent')
            payload = post.call_args.args[1]
            self.assertNotIn('comments', payload)
            self.assertIn('오류', payload['body'])

    def test_recheck_and_secret(self):
        repo, ident, sha, base = 'juny0955/pr-review-bot', 1466550689, 'a' * 40, 'b' * 40
        state = {'repo_id': ident, 'repo': repo, 'state': 'open', 'draft': False, 'sha': sha, 'base_sha': base}
        review = prepare_review(json.dumps({'body': '요약', 'comments': [
            {'path': 'src/a.py', 'line': 2, 'body': '오류'}]}), DIFF)
        post = Mock()
        with tempfile.TemporaryDirectory() as d, patch('publisher._require_revocation_gate', return_value=nullcontext()):
            pub = GitHubPublisher(post, Mock(side_effect=[state, dict(state, sha='c' * 40)]), {ident: repo}, enabled=True,
                                  single_vps_mvp=True, ledger_path=d + '/ledger', get=Mock(return_value=[]), diff=Mock(return_value=DIFF))
            with self.assertRaises(ValueError):
                pub.publish(ident, repo, 1, sha, review, base_sha=base)
            post.assert_not_called()
            secret = prepare_review(json.dumps({'body': '요약', 'comments': [
                {'path': 'src/a.py', 'line': 2, 'body': 'password="abcd1234"'}]}), DIFF)
            with self.assertRaises(ValueError):
                pub.publish(ident, repo, 1, sha, secret, base_sha=base)
            post.assert_not_called()

if __name__ == '__main__':
    unittest.main()
