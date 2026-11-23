import hashlib
import hmac
import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing, nullcontext, redirect_stdout
from unittest.mock import Mock, call, patch

from orchestrator import main, publication_loop
from publisher import GitHubPublisher
from worker import mode_provenance, result_provenance

REPOS = {1466550689: 'juny0955/pr-review-bot', 123: 'other/repo'}


class MultiRepoPublish(unittest.TestCase):
    def test_startup_accepts_configured_repositories(self):
        pairs = list(REPOS.items())
        configs = [(dict(pairs), 0), ({pairs[1][0]: pairs[1][1]}, 0),
                   ({}, 1), ({pairs[0][0]: pairs[1][1]}, 0),
                   ({456: 'another/project'}, 0)]
        with tempfile.TemporaryDirectory() as root:
            db = os.path.join(root, 'queue')
            open(db, 'w').close()
            for repos, expected in configs:
                with self.subTest(repos=repos), patch.dict(os.environ, {'WEBHOOK_SECRET': 'fake'}), \
                     patch('orchestrator.allowed', return_value=repos), patch('orchestrator.require_app_read_flag'), \
                     patch('orchestrator.GitHubReadOnly', return_value=Mock(auth=Mock(app_id=1, installation_id=2, key_path='fake'))), \
                     patch('orchestrator.app_read_auth'), patch('orchestrator.InstallationAuth'), \
                     patch('orchestrator.resolve_hermes_direct_adapter'), patch('orchestrator.Worker'), \
                     patch('orchestrator.threading.Thread'), patch('orchestrator.run_loop'), \
                     patch('orchestrator.signal.signal'), redirect_stdout(io.StringIO()):
                    self.assertEqual(main(['--db', db, '--wiki', root, '--repos', 'fake', '--single-vps-publish',
                                           '--enable-direct-inference', '--authorize-wiki-transfer', '--github-app-read',
                                           '--publication-ledger', root + '/ledger', '--publication-gate', root + '/gate']), expected)

    def test_scoped_publication_and_reconciliation(self):
        head, base, secret = 'a' * 40, 'b' * 40, 'fake'
        class Stop:
            count = 0
            def is_set(self): return self.count >= 3
            def wait(self, _): self.count += 1
        with tempfile.TemporaryDirectory() as root:
            db, ledger = os.path.join(root, 'queue'), os.path.join(root, 'ledger')
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.executescript('CREATE TABLE queue(delivery_id TEXT, body BLOB); CREATE TABLE work(delivery_id TEXT, status TEXT, result TEXT, publish_eligible INTEGER, notifications_enabled INTEGER, mode_provenance TEXT, result_provenance TEXT); CREATE TABLE webhook_signatures(delivery_id TEXT, signature TEXT);')
                for ident, name in REPOS.items():
                    delivery = str(ident)
                    body = json.dumps({'repository': {'id': ident, 'full_name': name}, 'number': 7, 'pull_request': {'number': 7, 'head': {'sha': head}, 'state': 'open', 'draft': False}, 'action': 'opened'}).encode()
                    result = json.dumps({'status': 'done', 'repo_id': ident, 'repository': name, 'number': 7, 'sha': head, 'base_sha': base, 'review': 'review'})
                    conn.execute('INSERT INTO queue VALUES (?,?)', (delivery, body))
                    conn.execute('INSERT INTO work VALUES (?,?,?,?,?,?,?)', (delivery, 'done', result, 1, 0, mode_provenance(secret, delivery, body, 1, 0), result_provenance(secret, delivery, body, 1, 0, result)))
                    conn.execute('INSERT INTO webhook_signatures VALUES (?,?)', (delivery, 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()))
            github, auth = Mock(), Mock()
            github.current.side_effect = lambda name, number: {'repo_id': next(i for i, n in REPOS.items() if n == name), 'repo': name, 'state': 'open', 'draft': False, 'sha': head, 'base_sha': base}
            auth.token.side_effect = lambda ident, name: (str(ident), 999)
            posted = {}
            def post(token, path, body):
                posted[path] = body
                raise TimeoutError()
            def get(token, path):
                return [{'commit_id': head, 'body': posted[path.split('?')[0]]['body']}]
            stop = Stop()
            with patch('publisher._require_revocation_gate', return_value=nullcontext()) as gate_mock, patch('orchestrator.time.monotonic', side_effect=lambda: stop.count * 5), patch('orchestrator.publish_transport', side_effect=post) as post_mock, patch('orchestrator.review_list_transport', side_effect=get) as get_mock:
                publication_loop(db, REPOS, github, auth, ledger, 'gate', secret, stop)
            self.assertTrue(any(c.args[1][:2] == [123, 'other/repo'] and c.kwargs == {'single_vps_mvp': True} for c in gate_mock.call_args_list))
            self.assertEqual(post_mock.call_count, 2)
            self.assertEqual(get_mock.call_count, 2)
            for ident, name in REPOS.items():
                path = '/repos/' + name + '/pulls/7/reviews'
                self.assertIn(call(ident, name), auth.token.call_args_list)
                self.assertTrue(any(c.args[:2] == (str(ident), path) for c in post_mock.call_args_list))
                self.assertTrue(any(c.args[0] == str(ident) and c.args[1].startswith(path + '?') for c in get_mock.call_args_list))

    def test_reject_mismatched_and_locally_disabled_pairs(self):
        head, base = 'a' * 40, 'b' * 40
        pairs = list(REPOS.items())
        for repos, ident, name in [({pairs[0][0]: pairs[0][1]}, pairs[0][0], pairs[1][1]), ({pairs[0][0]: pairs[0][1]}, *pairs[1])]:
            post = Mock()
            publisher = GitHubPublisher(post, Mock(), repos, enabled=True, single_vps_mvp=True)
            with self.assertRaises(ValueError):
                publisher.publish(ident, name, 7, head, 'review', base_sha=base)
            post.assert_not_called()


if __name__ == '__main__':
    unittest.main()
