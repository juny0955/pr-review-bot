import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock


class OrchestratorTests(unittest.TestCase):
    def test_continues_and_notifies_only_completed_jobs_without_review_content(self):
        from orchestrator import run_loop
        worker = Mock()
        worker.run_once.side_effect = [
            {'status': 'done', 'review': 'sensitive review'},
            {'status': 'skipped'}, None,
        ]
        notifier = Mock()
        stop = Mock()
        stop.is_set.side_effect = [False, False, False, True]
        stop.wait.return_value = False
        output = io.StringIO()
        with redirect_stdout(output):
            run_loop(worker, stop, notifier=notifier, channel='123', poll_interval=2)
        notifier.notify.assert_called_once_with('123', 'PR review completed (dry run).')
        stop.wait.assert_called_once_with(2)
        self.assertNotIn('sensitive review', output.getvalue())

    def test_failure_backoff_is_bounded_and_interruptible(self):
        from orchestrator import run_loop
        worker = Mock()
        worker.run_once.side_effect = [RuntimeError('secret'), RuntimeError('secret'), None]
        stop = Mock()
        stop.is_set.side_effect = [False, False, False, True]
        stop.wait.return_value = False
        output = io.StringIO()
        with redirect_stdout(output):
            run_loop(worker, stop, poll_interval=2, max_backoff=3)
        self.assertEqual([call.args[0] for call in stop.wait.call_args_list], [2, 3, 2])
        self.assertNotIn('secret', output.getvalue())

    def test_notification_failure_does_not_stop_next_job(self):
        from orchestrator import run_loop
        worker = Mock()
        worker.run_once.side_effect = [{'status': 'done'}, {'status': 'done'}]
        notifier = Mock()
        notifier.notify.side_effect = [RuntimeError('secret'), None]
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        output = io.StringIO()
        with redirect_stdout(output):
            run_loop(worker, stop, notifier=notifier, channel='123')
        self.assertEqual(notifier.notify.call_count, 2)
        self.assertNotIn('secret', output.getvalue())

    def test_invalid_worker_result_does_not_kill_loop_or_leak(self):
        from orchestrator import run_loop
        worker = Mock()
        worker.run_once.side_effect = ['secret', None]
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        output = io.StringIO()
        with redirect_stdout(output):
            run_loop(worker, stop, poll_interval=2)
        self.assertNotIn('secret', output.getvalue())
        self.assertEqual(worker.run_once.call_count, 2)

    def test_real_worker_persists_and_notifies_with_fake_adapters(self):
        from contextlib import closing
        import json
        import sqlite3
        import tempfile
        from pathlib import Path
        from notification import DiscordNotifier
        from orchestrator import run_loop
        from worker import Worker
        from test_worker import FakeGH, FakeModel, payload, sign_queue
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / 'queue.db'
            with closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE queue (delivery_id TEXT PRIMARY KEY, body BLOB)')
                conn.execute('INSERT INTO queue VALUES (?, ?)', ('id', json.dumps(payload()).encode()))
                sign_queue(conn, 'id', 'secret')
            wiki = root / 'wiki'
            wiki.mkdir()
            worker = Worker(str(db), FakeGH(), FakeModel(), wiki, {123: 'example-owner/example-repo'}, webhook_secret='secret')
            send = Mock()
            notifier = DiscordNotifier(['123'], send, enabled=True)
            stop = Mock()
            stop.is_set.side_effect = [False, False, True]
            with redirect_stdout(io.StringIO()):
                run_loop(worker, stop, notifier=notifier, channel='123')
            with closing(sqlite3.connect(db)) as conn, conn:
                self.assertEqual(conn.execute('SELECT status FROM work').fetchone()[0], 'done')
            send.assert_called_once_with('123', {'content': 'PR review completed (dry run).', 'allowed_mentions': {'parse': []}})

    def test_cli_requires_explicit_dry_run_and_direct_transfer_consent(self):
        from orchestrator import main
        with self.assertRaises(SystemExit):
            main(['--db', 'x', '--wiki', 'x', '--repos', 'x'])
