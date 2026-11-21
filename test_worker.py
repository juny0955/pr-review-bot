from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from receiver import create_server

SHA = 'a' * 40

def payload(**changes):
    pr = {'number': 1, 'draft': False, 'state': 'open', 'head': {'sha': SHA}}
    pr.update(changes)
    return {'action': 'opened', 'number': 1, 'repository': {'id': 123, 'full_name': 'example-owner/example-repo'}, 'pull_request': pr}

class WorkerTest(unittest.TestCase):
    def setUp(self):
        from worker import Worker
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / 'queue.db'
        server = create_server('secret', {123: 'example-owner/example-repo'}, str(self.db), 0)
        server.server_close()
        self.wiki = self.root / 'wiki'; self.wiki.mkdir()
        (self.wiki / 'guide.md').write_text('Review evidence', encoding='utf8')
        self.gh = FakeGH()
        self.model = FakeModel()
        self.worker = Worker(str(self.db), self.gh, self.model, self.wiki, {123: 'example-owner/example-repo'})

    def enqueue(self, data=None, delivery='id'):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('INSERT INTO queue(delivery_id, body) VALUES (?,?)', (delivery, json.dumps(data or payload()).encode()))

    def test_invalid_policy_is_retried_not_skipped(self):
        policy = self.root / 'policy.json'
        policy.write_text('{broken')
        self.worker.repos = policy
        self.enqueue()
        self.assertEqual(self.worker.run_once()['status'], 'retry')
        self.assertEqual(self.model.calls, [])

    def test_base_movement_during_review_discards_result(self):
        self.enqueue()
        states = iter([{'state': 'open', 'draft': False, 'sha': SHA, 'base_sha': 'b' * 40},
                       {'state': 'open', 'draft': False, 'sha': SHA, 'base_sha': 'c' * 40}])
        self.gh.current = lambda *args: next(states)
        self.assertEqual(self.worker.run_once()['status'], 'retry')

    def test_aba_base_movement_retries_before_model(self):
        from github_adapter import GitHubReadOnly
        from unittest.mock import patch
        gh = GitHubReadOnly({123: 'example-owner/example-repo'})
        a = {'state': 'open', 'draft': False, 'sha': SHA, 'base_sha': 'b' * 40}
        self.worker.github = gh
        self.enqueue()
        # Identical observations cannot rule out A -> B -> A inside a fetch.
        with patch.object(gh, 'current', return_value=a), patch('github_adapter._gh_get') as get:
            self.assertEqual(self.worker.run_once()['status'], 'retry')
            get.assert_not_called()
        self.assertEqual(self.model.calls, [])

    def test_unpublishable_model_reviews_are_retried(self):
        for index, review in enumerate(('', '   ', 'x' * 65537)):
            with self.subTest(length=len(review)):
                self.model.review = lambda request: review
                self.enqueue(delivery=str(index))
                self.assertEqual(self.worker.run_once()['status'], 'retry')

    def test_review_is_durable_and_not_repeated(self):
        self.enqueue()
        result = self.worker.run_once()
        self.assertEqual(result['status'], 'done')
        self.assertEqual(result['review'], 'fake review')
        self.assertEqual(result['base_sha'], 'b' * 40)
        self.assertEqual(self.model.calls[0]['wiki'][0]['text'], 'Review evidence')
        self.assertIsNone(self.worker.run_once())
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(json.loads(db.execute('SELECT result FROM work WHERE delivery_id=?', ('id',)).fetchone()[0]), result)

    def test_invalid_and_ineligible_events_never_reach_adapters(self):
        cases = [payload(draft=True), payload(state='closed'), payload(head={'sha': 'bad'}),
                 dict(payload(), action='closed'), dict(payload(), repository={'full_name':'evil/repo'}),
                 dict(payload(), number=True), {'bad': 'payload'}]
        for i, case in enumerate(cases):
            self.enqueue(case, str(i))
        for _ in cases:
            self.assertEqual(self.worker.run_once()['status'], 'skipped')
        self.assertEqual(self.model.calls, [])

    def test_repository_identity_and_rename_policy(self):
        bad = dict(payload(), repository={'id': 999, 'full_name': 'example-owner/example-repo'})
        self.assertEqual(self.worker.process(json.dumps(bad).encode())['status'], 'skipped')
        self.assertEqual(self.model.calls, [])
        self.worker.repos = {123: 'new/name'}
        self.assertEqual(self.worker.process(json.dumps(payload()).encode())['status'], 'skipped')
        renamed = dict(payload(), repository={'id': 123, 'full_name': 'new/name'})
        self.assertEqual(self.worker.process(json.dumps(renamed).encode())['status'], 'done')

    def test_stale_before_or_after_review_is_discarded(self):
        self.enqueue()
        self.gh.current = lambda *args: {'state': 'open', 'draft': False, 'sha': 'b' * 40}
        self.assertEqual(self.worker.run_once()['status'], 'skipped')
        self.assertEqual(self.model.calls, [])
        self.enqueue(delivery='second')
        states = iter([{'state':'open','draft':False,'sha':SHA,'base_sha':'b'*40}, {'state':'open','draft':True,'sha':SHA,'base_sha':'b'*40}])
        self.gh.current = lambda *args: next(states)
        self.assertEqual(self.worker.run_once()['status'], 'skipped')
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertNotIn('fake review', db.execute("SELECT result FROM work WHERE delivery_id='second'").fetchone()[0])

    def test_backoff_is_durable_and_does_not_starve_new_work(self):
        from worker import Worker
        now = [100]
        self.worker.clock = lambda: now[0]
        self.enqueue(delivery='first')
        self.enqueue(delivery='second')
        self.gh.current = lambda *args: (_ for _ in ()).throw(RuntimeError('secret'))
        self.assertEqual(self.worker.run_once()['status'], 'retry')
        restarted = Worker(str(self.db), FakeGH(), self.model, self.wiki, {123: 'example-owner/example-repo'}, clock=lambda: now[0])
        self.assertEqual(restarted.claim()[0], 'second')
        self.assertIsNone(restarted.claim())
        now[0] += 30
        self.assertEqual(restarted.claim()[0], 'first')

    def test_retry_and_lease_fencing(self):
        now = [100]
        self.worker.clock = lambda: now[0]
        self.enqueue()
        first = self.worker.claim()
        self.assertIsNone(self.worker.claim())
        now[0] += 301
        self.assertIsNone(self.worker.claim())
        now[0] += 29
        second = self.worker.claim()
        self.assertFalse(self.worker.finish(first[0], first[2], 'done', {'status':'done'}))
        self.assertTrue(self.worker.finish(second[0], second[2], 'retry', {'status':'retry'}))
        self.assertIsNone(self.worker.run_once())
        now[0] += 60
        self.assertEqual(self.worker.run_once()['status'], 'done')
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute('SELECT attempts FROM work').fetchone()[0], 3)

    def test_adapter_failure_is_retriable_without_leaking_error(self):
        now = [100]
        self.worker.clock = lambda: now[0]
        self.enqueue()
        def fail(*args): raise RuntimeError('secret credential')
        self.gh.current = fail
        self.assertEqual(self.worker.run_once(), {'status':'retry', 'reason':'processing failed'})
        self.gh.current = FakeGH().current
        self.assertIsNone(self.worker.run_once())
        now[0] += 30
        self.assertEqual(self.worker.run_once()['status'], 'done')

    def test_exponential_backoff_terminal_and_expired_final_lease(self):
        now = [100]
        self.worker.clock = lambda: now[0]
        self.enqueue()
        self.gh.current = lambda *args: (_ for _ in ()).throw(RuntimeError('secret'))
        for delay in (30, 60):
            self.assertEqual(self.worker.run_once()['status'], 'retry')
            now[0] += delay - 1
            self.assertIsNone(self.worker.run_once())
            now[0] += 1
        self.assertEqual(self.worker.run_once(), {'status':'failed', 'reason':'processing failed'})
        self.assertIsNone(self.worker.run_once())
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT status,attempts,next_attempt_at FROM work').fetchone(), ('failed', 3, None))
        self.enqueue(delivery='crash')
        for delay in (30, 60, 0):
            claim = self.worker.claim()
            self.assertEqual(claim[0], 'crash')
            now[0] += 300 + delay
        self.assertIsNone(self.worker.claim())
        self.assertFalse(self.worker.finish(*[claim[0], claim[2], 'done', {'status':'done'}]))
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("SELECT status,attempts FROM work WHERE delivery_id='crash'").fetchone(), ('failed', 3))

    def test_concurrent_claim_is_exclusive(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from worker import Worker
        self.enqueue()
        workers = [Worker(str(self.db), self.gh, self.model, self.wiki, {123: 'example-owner/example-repo'}) for _ in range(8)]
        barrier = Barrier(len(workers))
        def claim(worker):
            barrier.wait()
            return worker.claim()
        with ThreadPoolExecutor(max_workers=len(workers)) as pool:
            results = list(pool.map(claim, workers))
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_migration_preserves_legacy_retry(self):
        from worker import Worker
        self.enqueue()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('DROP TABLE work')
            db.execute('CREATE TABLE work (delivery_id TEXT PRIMARY KEY, status TEXT NOT NULL, lease_token TEXT, lease_until REAL, attempts INTEGER NOT NULL DEFAULT 0, result TEXT)')
            db.execute("INSERT INTO work(delivery_id,status,attempts) VALUES ('id','retry',1)")
        worker = Worker(str(self.db), self.gh, self.model, self.wiki, {123: 'example-owner/example-repo'}, clock=lambda: 100)
        self.assertEqual(worker.run_once()['status'], 'done')

    def test_wiki_symlink_and_oversized_file_are_excluded(self):
        from worker import wiki_evidence
        (self.wiki / 'escape.md').symlink_to('/etc/passwd')
        (self.wiki / 'large.md').write_text('a' * 16385)
        self.assertEqual(wiki_evidence(self.wiki), [{'path':'guide.md','text':'Review evidence'}])

    def test_vault_layout_retrieves_index_and_relevant_article(self):
        articles = self.wiki / 'wiki'
        articles.mkdir()
        (articles / 'index.md').write_text('Article index', encoding='utf8')
        for i in range(25):
            (articles / f'a{i:02}.md').write_text('unrelated material', encoding='utf8')
        (articles / 'rfsync QUIC.md').write_text('QUIC transport rules', encoding='utf8')
        (self.wiki / 'outside.md').write_text('QUIC outside', encoding='utf8')
        self.gh.diff = lambda *args: 'diff --git a/transport/quic.rs b/transport/quic.rs'
        self.enqueue()
        self.assertEqual(self.worker.run_once()['status'], 'done')
        evidence = self.model.calls[0]['wiki']
        self.assertEqual(evidence[0], {'path': 'wiki/index.md', 'text': 'Article index'})
        self.assertIn({'path': 'wiki/rfsync QUIC.md', 'text': 'QUIC transport rules'}, evidence)
        self.assertNotIn('outside.md', [entry['path'] for entry in evidence])
        self.assertLessEqual(len(evidence), 20)

    def test_vault_article_directory_symlink_is_rejected(self):
        from worker import wiki_evidence
        (self.wiki / 'wiki').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            wiki_evidence(self.wiki, 'secret')

    def test_article_symlink_and_invalid_text_are_excluded(self):
        from worker import wiki_evidence
        articles = self.wiki / 'wiki'
        articles.mkdir()
        (articles / 'index.md').write_text('index')
        (articles / 'leak.md').symlink_to(self.wiki / 'guide.md')
        (articles / 'bad.md').write_bytes(b'\xff')
        self.assertEqual(wiki_evidence(self.wiki), [{'path': 'wiki/index.md', 'text': 'index'}])

    def test_oversized_diff_skips_without_model(self):
        self.enqueue()
        self.gh.diff = lambda *args: 'x' * (1024 * 1024 + 1)
        self.assertEqual(self.worker.run_once()['status'], 'skipped')
        self.assertEqual(self.model.calls, [])

class FakeGH:
    def current(self, repo, number):
        return {'state': 'open', 'draft': False, 'sha': SHA, 'base_sha': 'b' * 40}
    def diff(self, repo, number, sha, base_sha):
        return 'diff text'

class FakeModel:
    def __init__(self): self.calls = []
    def review(self, request):
        self.calls.append(request)
        return 'fake review'

if __name__ == '__main__': unittest.main()
