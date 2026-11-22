import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import orchestrator
import runner
from test_worker import FakeModel, payload


class AppCLITest(unittest.TestCase):
    def test_cli_to_worker_and_redaction(self):
        for module in (runner, orchestrator):
            for failure in (False, True):
                with self.subTest(module=module.__name__, failure=failure), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    db, wiki, repos = root / 'db', root / 'wiki', root / 'repos'
                    wiki.mkdir()
                    (wiki / 'index.md').write_text('synthetic evidence')
                    repos.write_text(json.dumps({'repositories': [{'id': 123, 'full_name': 'example-owner/example-repo', 'enabled': True}]}))
                    with closing(sqlite3.connect(db)) as conn, conn:
                        conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
                        conn.execute('INSERT INTO queue VALUES (?, ?)', ('id', json.dumps(payload()).encode()))
                    args = ['--db', str(db), '--wiki', str(wiki), '--repos', str(repos), '--dry-run',
                            '--enable-direct-inference', '--authorize-wiki-transfer', '--github-app-read']
                    env = {'GITHUB_APP_ID': '1234', 'GITHUB_APP_INSTALLATION_ID': '5678', 'GITHUB_APP_KEY_PATH': '/synthetic/key'}
                    response = {'number': 1, 'state': 'open', 'draft': False, 'head': {'sha': 'a' * 40},
                                'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': 'example-owner/example-repo', 'private': False}}}
                    model = FakeModel()
                    output, errors = io.StringIO(), io.StringIO()
                    def run_one(worker, stop):
                        worker.run_once()
                    with patch.dict('os.environ', env, clear=True), \
                         patch('github_app_auth.InstallationAuth._token', side_effect=RuntimeError('SYNTHETIC_SECRET') if failure else None, return_value=('fake-token', 1)) as token, \
                         patch('github_adapter.read_transport', return_value=response) as read, \
                         patch('github_adapter._pinned_diff', return_value='synthetic diff') as diff, \
                         patch('github_adapter._gh_get', side_effect=AssertionError('gh fallback')), \
                         patch.object(module, 'resolve_hermes_direct_adapter', return_value=model), \
                         patch('orchestrator.run_loop', side_effect=run_one), \
                         redirect_stdout(output), redirect_stderr(errors):
                        code = module.main(args)
                    self.assertEqual(code, 1 if failure and module is runner else 0)
                    with closing(sqlite3.connect(db)) as conn:
                        result = json.loads(conn.execute('SELECT result FROM work').fetchone()[0])
                    self.assertEqual(result['status'], 'retry' if failure else 'done')
                    self.assertNotIn('SYNTHETIC_SECRET', output.getvalue() + errors.getvalue() + json.dumps(result))
                    self.assertGreaterEqual(token.call_count, 1)
                    if failure:
                        read.assert_not_called()
                        diff.assert_not_called()
                        self.assertEqual(model.calls, [])
                    else:
                        self.assertGreaterEqual(read.call_count, 4)
                        diff.assert_called_once_with('https://github.com/example-owner/example-repo.git', 1, 'a' * 40, 'b' * 40, public_only=True)
                        self.assertEqual(model.calls[0]['model'], 'gpt-6.1-terra')
                        self.assertEqual(model.calls[0]['profile'], 'prreview')

    def test_implicit_app_configuration_never_falls_back_to_gh(self):
        names = ('GITHUB_APP_ID', 'GITHUB_APP_INSTALLATION_ID', 'GITHUB_APP_KEY_PATH')
        environments = [{name: value} for name in names for value in ('SYNTHETIC_SECRET', '')]
        environments.append(dict(zip(names, ('1234', '5678', '/synthetic/key'))))
        for module in (runner, orchestrator):
            for env in environments:
                with self.subTest(module=module.__name__, env=env), tempfile.TemporaryDirectory() as directory:
                    db = Path(directory) / 'db'
                    db.touch()
                    args = ['--db', str(db), '--wiki', 'fake', '--repos', 'fake', '--dry-run',
                            '--enable-direct-inference', '--authorize-wiki-transfer']
                    output, errors = io.StringIO(), io.StringIO()
                    with patch.dict('os.environ', env, clear=True), patch.object(module, 'allowed'), \
                         patch.object(module, 'GitHubReadOnly') as github, patch.object(module, 'Worker') as worker, \
                         patch.object(module, 'resolve_hermes_direct_adapter') as resolver, \
                         patch('github_adapter._gh_get') as gh, patch.object(runner, 'run_once', return_value=None), \
                         patch.object(orchestrator, 'run_loop'), redirect_stdout(output), redirect_stderr(errors):
                        self.assertEqual(module.main(args), 1)
                    self.assertEqual(json.loads(output.getvalue()), {'status': 'error'})
                    self.assertEqual(errors.getvalue(), '')
                    github.assert_not_called()
                    worker.assert_not_called()
                    resolver.assert_not_called()
                    gh.assert_not_called()

    def test_no_app_environment_keeps_legacy_gh(self):
        for module in (runner, orchestrator):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                db = Path(directory) / 'db'
                db.touch()
                args = ['--db', str(db), '--wiki', 'fake', '--repos', 'fake', '--dry-run',
                        '--enable-direct-inference', '--authorize-wiki-transfer']
                with patch.dict('os.environ', {}, clear=True), patch.object(module, 'allowed'), \
                     patch.object(module, 'GitHubReadOnly') as github, patch.object(module, 'Worker'), \
                     patch.object(module, 'resolve_hermes_direct_adapter'), \
                     patch.object(runner, 'run_once', return_value=None), \
                     patch('orchestrator.run_loop'), redirect_stdout(io.StringIO()):
                    self.assertEqual(module.main(args), 0)
                github.assert_called_once_with('fake')

    def test_missing_or_invalid_environment_fails_before_worker(self):
        for module in (runner, orchestrator):
            for env in ({}, {'GITHUB_APP_ID': '1', 'GITHUB_APP_INSTALLATION_ID': '2'},
                        {'GITHUB_APP_ID': 'SYNTHETIC_SECRET', 'GITHUB_APP_INSTALLATION_ID': '2', 'GITHUB_APP_KEY_PATH': '/key'}):
                with self.subTest(module=module.__name__, env=env), tempfile.TemporaryDirectory() as directory:
                    db = Path(directory) / 'db'
                    db.touch()
                    args = ['--db', str(db), '--wiki', 'fake', '--repos', 'fake', '--dry-run',
                            '--enable-direct-inference', '--authorize-wiki-transfer', '--github-app-read']
                    output, errors = io.StringIO(), io.StringIO()
                    with patch.dict('os.environ', env, clear=True), patch.object(module, 'allowed'), \
                         patch.object(module, 'Worker') as worker, patch.object(module, 'resolve_hermes_direct_adapter') as resolver, \
                         redirect_stdout(output), redirect_stderr(errors):
                        self.assertEqual(module.main(args), 1)
                    self.assertEqual(json.loads(output.getvalue()), {'status': 'error'})
                    self.assertEqual(errors.getvalue(), '')
                    worker.assert_not_called()
                    resolver.assert_not_called()


if __name__ == '__main__':
    unittest.main()
