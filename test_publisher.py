import unittest
from unittest.mock import Mock
from publisher import GitHubPublisher

REPO = 'example-owner/example-repo'
ID = 123456789
SHA = 'a' * 40
POLICY = {ID: REPO}


def fresh(**overrides):
    return dict({'state': 'open', 'draft': False, 'sha': SHA,
                 'repo_id': ID, 'repo': REPO}, **overrides)


class PublisherTests(unittest.TestCase):
    def test_default_is_dry_run(self):
        post, current = Mock(), Mock()
        self.assertEqual(GitHubPublisher(post, current, POLICY).publish(ID, REPO, 1, SHA, 'review'), 'dry_run')
        post.assert_not_called()
        current.assert_not_called()

    def test_enabled_posts_comment_at_sha_after_freshness_check(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            post, current = Mock(), Mock(return_value=fresh())
            publisher = GitHubPublisher(post, current, POLICY, enabled=True,
                                        ledger_path=Path(directory) / 'ledger', get=Mock())
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review'), 'sent')
            current.assert_called_once_with(REPO, 7)
            path, payload = post.call_args.args
            self.assertEqual(path, 'repos/example-owner/example-repo/pulls/7/reviews')
            self.assertEqual(payload['commit_id'], SHA)
            self.assertEqual(payload['event'], 'COMMENT')
            self.assertTrue(payload['body'].startswith('review\n\n<!-- pr-review-bot:'))

    def test_rejects_spoofed_fresh_identity(self):
        for response in (fresh(repo_id=ID + 1), fresh(repo='other/repo'),
                         fresh(repo_id=True), {'state': 'open', 'draft': False, 'sha': SHA}):
            with self.subTest(response=response):
                post = Mock()
                with self.assertRaises(ValueError):
                    GitHubPublisher(post, Mock(return_value=response), POLICY, enabled=True).publish(ID, REPO, 1, SHA, 'review')
                post.assert_not_called()

    def test_rejects_invalid_inputs_and_implicit_enable(self):
        post, current = Mock(), Mock()
        with self.assertRaises(ValueError):
            GitHubPublisher(post, current, POLICY, enabled='false')
        publisher = GitHubPublisher(post, current, POLICY, enabled=True)
        for ident, repo, number, sha, review in [(ID + 1, REPO, 1, SHA, 'x'), (True, REPO, 1, SHA, 'x'),
                                                   (ID, 'other/repo', 1, SHA, 'x'), (ID + 1, None, 1, SHA, 'x'), (ID, REPO, True, SHA, 'x'),
                                                   (ID, REPO, 1, 'abc', 'x'), (ID, REPO, 1, SHA, ''),
                                                   (ID, REPO, 1, SHA, 'x' * 65537)]:
            with self.subTest(ident=ident, repo=repo, number=number, sha=sha, length=len(review)), self.assertRaises(ValueError):
                publisher.publish(ident, repo, number, sha, review)
        post.assert_not_called()
        current.assert_not_called()

    def test_stale_review_is_not_posted(self):
        post = Mock()
        with self.assertRaises(ValueError):
            GitHubPublisher(post, Mock(return_value=fresh(sha='b' * 40)), POLICY, enabled=True).publish(ID, REPO, 1, SHA, 'review')
        post.assert_not_called()


class LedgerTests(unittest.TestCase):
    def test_repeated_publication_is_durable_and_only_posts_once(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'ledger.sqlite')
            post = Mock()
            kwargs = dict(enabled=True, ledger_path=path, get=Mock(return_value=[]))
            self.assertEqual(GitHubPublisher(post, Mock(return_value=fresh()), POLICY, **kwargs).publish(ID, REPO, 7, SHA, 'review'), 'sent')
            self.assertEqual(GitHubPublisher(post, Mock(return_value=fresh()), POLICY, **kwargs).publish(ID, REPO, 7, SHA, 'review'), 'sent')
            self.assertEqual(post.call_count, 1)

    def test_ambiguous_post_reconciles_only_positive_marker(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ledger'
            post = Mock(side_effect=TimeoutError())
            get = Mock(return_value=[])
            publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY,
                                        enabled=True, ledger_path=path, get=get)
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review'), 'ambiguous')
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review'), 'ambiguous')
            body = post.call_args.args[1]['body']
            get.return_value = [{'commit_id': SHA, 'body': body}]
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review'), 'sent')
            self.assertEqual(post.call_count, 1)

    def test_fails_closed_without_durable_ledger(self):
        post = Mock()
        publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True)
        with self.assertRaises(ValueError):
            publisher.publish(ID, REPO, 1, SHA, 'review')
        post.assert_not_called()

    def test_get_failure_never_retries_post(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            post = Mock(side_effect=TimeoutError())
            publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True,
                                        ledger_path=Path(directory) / 'ledger', get=Mock(side_effect=TimeoutError()))
            self.assertEqual(publisher.publish(ID, REPO, 1, SHA, 'review'), 'ambiguous')
            self.assertEqual(publisher.publish(ID, REPO, 1, SHA, 'review'), 'ambiguous')
            self.assertEqual(post.call_count, 1)

    def test_file_uri_memory_ledger_is_rejected(self):
        post = Mock()
        publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True,
                                    ledger_path='file:volatile?mode=memory&cache=shared', get=Mock())
        with self.assertRaises(ValueError):
            publisher.publish(ID, REPO, 1, SHA, 'review')
        post.assert_not_called()
