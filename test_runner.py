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

    def test_missing_db_is_not_created(self):
        from runner import run_once
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / 'missing'
            with self.assertRaises(ValueError):
                run_once(db, directory, {}, github=FakeGH(), model=FakeModel())
            self.assertFalse(db.exists())

if __name__ == '__main__':
    unittest.main()
