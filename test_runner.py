from contextlib import closing, redirect_stderr, redirect_stdout
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_worker import FakeGH, FakeModel, payload


class RunnerTest(unittest.TestCase):
    def test_injected_run_persists_one_result(self):
        from runner import run_once
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / 'queue.sqlite3'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
                conn.execute('INSERT INTO queue VALUES (?, ?)', ('one', json.dumps(payload()).encode()))
            wiki = root / 'wiki'
            wiki.mkdir()
            (wiki / 'index.md').write_text('fixture evidence')
            model = FakeModel()
            result = run_once(db, wiki, {123: 'example-owner/example-repo'}, github=FakeGH(), model=model)
            self.assertEqual(result['status'], 'done')
            self.assertEqual(model.calls[0]['wiki'][0]['text'], 'fixture evidence')
            with closing(sqlite3.connect(db)) as conn, conn:
                self.assertEqual(json.loads(conn.execute('SELECT result FROM work').fetchone()[0]), result)
            self.assertIsNone(run_once(db, wiki, {123: 'example-owner/example-repo'}, github=FakeGH(), model=model))

    def test_cli_argument_errors_are_fixed_and_help_works(self):
        import runner
        import orchestrator
        valid = ['--db', 'db', '--wiki', 'wiki', '--repos', 'repos',
                 '--dry-run', '--enable-direct-inference', '--authorize-wiki-transfer']
        for module in (runner, orchestrator):
            for args in (valid + ['--unknown', 'SYNTHETIC_SECRET'],
                         valid + ['--db=SYNTHETIC_SECRET', '--dry-run=SYNTHETIC_SECRET'],
                         ['--db'], valid[:-1]):
                with self.subTest(module=module.__name__, args=args):
                    output, errors = io.StringIO(), io.StringIO()
                    with redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as exc:
                        module.main(args)
                    self.assertEqual(exc.exception.code, 2)
                    self.assertEqual(output.getvalue(), '')
                    self.assertEqual(errors.getvalue(), 'error: invalid arguments\n')
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(SystemExit) as exc:
                module.main(['--help'])
            self.assertEqual(exc.exception.code, 0)
            self.assertIn('usage:', output.getvalue())

    def test_cli_worker_status_allowlist(self):
        import runner
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            db.touch()
            args = ['--db', str(db), '--wiki', 'fake', '--repos', 'fake',
                    '--dry-run', '--enable-direct-inference', '--authorize-wiki-transfer']
            cases = [(None, 'idle', 0), ({'status': 'done'}, 'done', 0),
                     ({'status': 'skipped'}, 'skipped', 0),
                     *[({'status': status}, status, 1) for status in ('retry', 'failed', 'lease_lost')],
                     ({'status': 'SYNTHETIC_SECRET'}, 'error', 1),
                     ({}, 'error', 1), ({'status': []}, 'error', 1)]
            for result, expected, code in cases:
                with self.subTest(result=result):
                    output = io.StringIO()
                    with patch.object(runner, 'allowed'), patch.object(runner, 'GitHubReadOnly'), \
                         patch.object(runner, 'resolve_hermes_direct_adapter'), \
                         patch.object(runner, 'run_once', return_value=result), redirect_stdout(output):
                        self.assertEqual(runner.main(args), code)
                    self.assertEqual(json.loads(output.getvalue()), {'status': expected})

    def test_cli_requires_explicit_flags_before_resolving_client(self):
        from runner import main
        with patch('runner.resolve_hermes_direct_adapter') as resolver:
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['--db', 'unused', '--wiki', 'unused', '--repos', 'unused'])
            resolver.assert_not_called()

    def test_cli_wires_adapters_and_prints_status_only(self):
        from runner import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db, wiki, repos = root / 'queue', root / 'wiki', root / 'repos.json'
            wiki.mkdir()
            (wiki / 'index.md').write_text('fixture')
            repos.write_text(json.dumps({'repositories': [{'id': 123, 'full_name': 'example-owner/example-repo', 'enabled': True}]}))
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
                conn.execute('INSERT INTO queue VALUES (?, ?)', ('one', json.dumps(payload()).encode()))
            output = io.StringIO()
            with patch('runner.GitHubReadOnly', return_value=FakeGH()), patch('runner.resolve_hermes_direct_adapter', return_value=FakeModel()), redirect_stdout(output):
                code = main(['--db', str(db), '--wiki', str(wiki), '--repos', str(repos), '--dry-run', '--enable-direct-inference', '--authorize-wiki-transfer'])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue()), {'status': 'done'})
            with closing(sqlite3.connect(db)) as conn:
                self.assertEqual(json.loads(conn.execute('SELECT result FROM work').fetchone()[0])['review'], 'fake review')

    def test_cli_isolation_lock_and_other_errors_are_distinct_and_redacted(self):
        from model_adapter import IsolationUnavailable
        import orchestrator
        import runner
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            db.touch()
            args = ['--db', str(db), '--wiki', 'fake-wiki', '--repos', 'fake-repos',
                    '--dry-run', '--enable-direct-inference', '--authorize-wiki-transfer']
            for module in (runner, orchestrator):
                for error, status in ((IsolationUnavailable('secret lock'), 'isolation_unavailable'),
                                      (RuntimeError('secret error'), 'error')):
                    with self.subTest(module=module.__name__, status=status):
                        output, errors = io.StringIO(), io.StringIO()
                        with patch.object(module, 'allowed'), patch.object(module, 'GitHubReadOnly'), \
                             patch.object(module, 'resolve_hermes_direct_adapter', side_effect=error), \
                             patch.object(module, 'Worker') as worker, redirect_stdout(output), redirect_stderr(errors):
                            self.assertEqual(module.main(args), 1)
                        self.assertEqual(json.loads(output.getvalue()), {'status': status})
                        self.assertEqual(errors.getvalue(), '')
                        worker.assert_not_called()

    def test_actual_lock_prevents_notification_start(self):
        import orchestrator
        import runner
        from types import SimpleNamespace
        modules = {'hermes_cli': SimpleNamespace(), 'hermes_cli.profiles': SimpleNamespace(get_active_profile_name=lambda: 'developer')}
        with patch.dict('sys.modules', modules), tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'queue'
            db.touch()
            args = ['--db', str(db), '--wiki', 'fake-wiki', '--repos', 'fake-repos',
                    '--dry-run', '--enable-direct-inference', '--authorize-wiki-transfer']
            for module in (runner, orchestrator):
                output = io.StringIO()
                with self.subTest(module=module.__name__), patch.object(module, 'allowed'), \
                     patch.object(module, 'GitHubReadOnly'), patch.object(module, 'Worker') as worker, \
                     patch('orchestrator.DiscordTransport'), patch('orchestrator.DiscordNotifier'), \
                     patch.dict('os.environ', {'DISCORD_CHANNEL_ID': '123'}, clear=True), \
                     patch('orchestrator.threading.Thread') as thread, redirect_stdout(output):
                    extra = ['--enable-discord-notifications'] if module is orchestrator else []
                    self.assertEqual(module.main(args + extra), 1)
                self.assertEqual(json.loads(output.getvalue()), {'status': 'isolation_unavailable'})
                worker.assert_not_called()
                thread.assert_not_called()

    def test_missing_db_is_not_created(self):
        from runner import run_once
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'missing'
            with self.assertRaises(ValueError):
                run_once(db, directory, {}, github=FakeGH(), model=FakeModel())
            self.assertFalse(db.exists())

if __name__ == '__main__':
    unittest.main()
