import unittest
from unittest.mock import Mock, patch
from publisher import GitHubPublisher

REPO = 'example-owner/example-repo'
ID = 123456789
SHA = 'a' * 40
POLICY = {ID: REPO}


def fresh(**overrides):
    return dict({'state': 'open', 'draft': False, 'sha': SHA,
                 'repo_id': ID, 'repo': REPO, 'base_sha': 'b' * 40}, **overrides)


class PublisherTests(unittest.TestCase):
    def test_enabled_fails_closed_without_revocation_gate(self):
        import tempfile
        from pathlib import Path
        post = Mock()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'no shared revocation gate'):
                GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True,
                                ledger_path=Path(directory) / 'ledger', get=Mock()).publish(
                    ID, REPO, 1, SHA, 'review', base_sha='b' * 40)
        post.assert_not_called()

    def setUp(self):
        if self._testMethodName != 'test_enabled_fails_closed_without_revocation_gate':
            gate = patch('publisher._require_revocation_gate')
            gate.start()
            self.addCleanup(gate.stop)

    def test_rejects_changed_or_missing_base_without_post(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            post = Mock()
            publisher = GitHubPublisher(post, Mock(return_value=fresh(base_sha='c' * 40)), POLICY,
                                        enabled=True, ledger_path=Path(directory) / 'ledger', get=Mock())
            with self.assertRaises(ValueError):
                publisher.publish(ID, REPO, 1, SHA, 'review', base_sha='b' * 40)
            with self.assertRaises(ValueError):
                publisher.publish(ID, REPO, 1, SHA, 'review')
            post.assert_not_called()

    def test_default_is_dry_run(self):
        post, current = Mock(), Mock()
        self.assertEqual(GitHubPublisher(post, current, POLICY).publish(ID, REPO, 1, SHA, 'review', base_sha='b' * 40), 'dry_run')
        post.assert_not_called()
        current.assert_not_called()

    def test_enabled_posts_comment_at_sha_after_freshness_check(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            post, current = Mock(), Mock(return_value=fresh())
            publisher = GitHubPublisher(post, current, POLICY, enabled=True,
                                        ledger_path=Path(directory) / 'ledger', get=Mock())
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'sent')
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
                    GitHubPublisher(post, Mock(return_value=response), POLICY, enabled=True).publish(ID, REPO, 1, SHA, 'review', base_sha='b' * 40)
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
                publisher.publish(ident, repo, number, sha, review, base_sha='b' * 40)
        post.assert_not_called()
        current.assert_not_called()

    def test_stale_review_is_not_posted(self):
        post = Mock()
        with self.assertRaises(ValueError):
            GitHubPublisher(post, Mock(return_value=fresh(sha='b' * 40)), POLICY, enabled=True).publish(ID, REPO, 1, SHA, 'review', base_sha='b' * 40)
        post.assert_not_called()


class LedgerTests(unittest.TestCase):
    def setUp(self):
        # Exercise dormant ledger code only; no real transport is used.
        gate = patch('publisher._require_revocation_gate')
        gate.start()
        self.addCleanup(gate.stop)
    def test_new_claim_blocks_legacy_claim_before_post(self):
        from contextlib import closing
        import hashlib, json, sqlite3, tempfile
        from pathlib import Path
        key = hashlib.sha256(json.dumps([ID, REPO, 7, SHA, 'review'], ensure_ascii=True,
                                        separators=(',', ':')).encode()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ledger'
            def old_claim(*args):
                with closing(sqlite3.connect(path)) as db, db:
                    inserted = db.execute('INSERT OR IGNORE INTO publications VALUES (?, ?, ?)',
                                          (key, 'old-marker', 'pending')).rowcount
                self.assertEqual(inserted, 0)
            publisher = GitHubPublisher(old_claim, Mock(return_value=fresh()), POLICY,
                                        enabled=True, ledger_path=path, get=Mock(return_value=[]))
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'sent')

    def test_migrates_v2_claim_by_reserving_legacy_key_without_reposting(self):
        from contextlib import closing
        import hashlib, json, sqlite3, tempfile
        from pathlib import Path
        def digest(value):
            return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        legacy = digest([ID, REPO, 7, SHA, 'review'])
        v2 = digest(['v2', ID, REPO, 7, SHA, 'b' * 40, 'review'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ledger'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE publications (key TEXT PRIMARY KEY, marker TEXT NOT NULL, state TEXT NOT NULL)')
                db.execute('INSERT INTO publications VALUES (?, ?, ?)', (v2, 'v2-marker', 'sent'))
            post = Mock()
            publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY,
                                        enabled=True, ledger_path=path, get=Mock())
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'sent')
            with closing(sqlite3.connect(path)) as db, db:
                self.assertEqual(db.execute('INSERT OR IGNORE INTO publications VALUES (?, ?, ?)',
                                            (legacy, 'old-marker', 'pending')).rowcount, 0)
            post.assert_not_called()

    def test_failed_v2_claim_rolls_back_legacy_reservation(self):
        from contextlib import closing
        import sqlite3, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ledger'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE publications (key TEXT PRIMARY KEY, marker TEXT NOT NULL, state TEXT NOT NULL)')
                db.execute("CREATE TRIGGER fail_v2 BEFORE INSERT ON publications WHEN NEW.marker LIKE '<!--%' BEGIN SELECT RAISE(ABORT, 'failed'); END")
            post = Mock()
            publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY,
                                        enabled=True, ledger_path=path, get=Mock())
            with self.assertRaises(sqlite3.DatabaseError):
                publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40)
            with closing(sqlite3.connect(path)) as db, db:
                self.assertEqual(db.execute('SELECT count(*) FROM publications').fetchone()[0], 0)
            post.assert_not_called()

    def test_different_bases_have_distinct_publications(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            post = Mock()
            current = Mock(return_value=fresh())
            publisher = GitHubPublisher(post, current, POLICY, enabled=True,
                                        ledger_path=Path(directory) / 'ledger', get=Mock(return_value=[]))
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'sent')
            current.return_value = fresh(base_sha='c' * 40)
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='c' * 40), 'sent')
            self.assertEqual(post.call_count, 2)
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='c' * 40), 'sent')
            self.assertEqual(post.call_count, 2)

    def test_legacy_ledger_claim_prevents_duplicate_post(self):
        from contextlib import closing
        import hashlib, json, sqlite3, tempfile
        from pathlib import Path
        key = hashlib.sha256(json.dumps([ID, REPO, 7, SHA, 'review'], ensure_ascii=True,
                                        separators=(',', ':')).encode()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ledger'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE publications (key TEXT PRIMARY KEY, marker TEXT NOT NULL, state TEXT NOT NULL)')
                db.execute('INSERT INTO publications VALUES (?, ?, ?)', (key, 'marker', 'sent'))
            post = Mock()
            get = Mock(return_value=[{'commit_id': SHA, 'body': 'marker'}])
            publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True,
                                        ledger_path=path, get=get)
            for state in ('sent', 'pending', 'ambiguous'):
                with self.subTest(state=state):
                    with closing(sqlite3.connect(path)) as db, db:
                        db.execute('UPDATE publications SET state = ? WHERE key = ?', (state, key))
                    for base in ('b' * 40, 'c' * 40):
                        publisher.current.return_value = fresh(base_sha=base)
                        self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha=base), 'ambiguous')
            post.assert_not_called()

    def test_repeated_publication_is_durable_and_only_posts_once(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'ledger.sqlite')
            post = Mock()
            kwargs = dict(enabled=True, ledger_path=path, get=Mock(return_value=[]))
            self.assertEqual(GitHubPublisher(post, Mock(return_value=fresh()), POLICY, **kwargs).publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'sent')
            self.assertEqual(GitHubPublisher(post, Mock(return_value=fresh()), POLICY, **kwargs).publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'sent')
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
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'ambiguous')
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'ambiguous')
            body = post.call_args.args[1]['body']
            get.return_value = [{'commit_id': SHA, 'body': body}]
            self.assertEqual(publisher.publish(ID, REPO, 7, SHA, 'review', base_sha='b' * 40), 'sent')
            self.assertEqual(post.call_count, 1)

    def test_fails_closed_without_durable_ledger(self):
        post = Mock()
        publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True)
        with self.assertRaises(ValueError):
            publisher.publish(ID, REPO, 1, SHA, 'review', base_sha='b' * 40)
        post.assert_not_called()

    def test_get_failure_never_retries_post(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            post = Mock(side_effect=TimeoutError())
            publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True,
                                        ledger_path=Path(directory) / 'ledger', get=Mock(side_effect=TimeoutError()))
            self.assertEqual(publisher.publish(ID, REPO, 1, SHA, 'review', base_sha='b' * 40), 'ambiguous')
            self.assertEqual(publisher.publish(ID, REPO, 1, SHA, 'review', base_sha='b' * 40), 'ambiguous')
            self.assertEqual(post.call_count, 1)

    def test_file_uri_memory_ledger_is_rejected(self):
        post = Mock()
        publisher = GitHubPublisher(post, Mock(return_value=fresh()), POLICY, enabled=True,
                                    ledger_path='file:volatile?mode=memory&cache=shared', get=Mock())
        with self.assertRaises(ValueError):
            publisher.publish(ID, REPO, 1, SHA, 'review', base_sha='b' * 40)
        post.assert_not_called()
