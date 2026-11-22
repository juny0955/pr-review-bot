import contextlib
import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

import orchestrator as o


class RegressionTests(unittest.TestCase):
    def test_job_error_test_closes_all_database_connections(self):
        connections = []
        class Connection(sqlite3.Connection):
            closed = False
            def close(self):
                self.closed = True
                super().close()
        connect = sqlite3.connect
        def tracked_connect(*args, **kwargs):
            conn = connect(*args, **kwargs, factory=Connection)
            connections.append(conn)
            return conn
        with patch('sqlite3.connect', side_effect=tracked_connect):
            self.test_job_errors_are_safe_rate_limited_and_do_not_block_other_jobs()
        self.assertTrue(connections)
        self.assertTrue(all(conn.closed for conn in connections))

    def test_job_errors_are_safe_rate_limited_and_do_not_block_other_jobs(self):
        with tempfile.TemporaryDirectory() as root:
            db = os.path.join(root, 'queue')
            with contextlib.closing(sqlite3.connect(db)) as conn, conn:
                conn.execute('CREATE TABLE work(delivery_id TEXT, status TEXT, publish_eligible INTEGER)')
                conn.executemany('INSERT INTO work VALUES (?, ?, ?)', [('bad', 'done', 1), ('good', 'done', 1)])
            class Stop:
                count = 0
                def is_set(self): return self.count >= 3
                def wait(self, _): self.count += 1
            def publish(_db, delivery, **kwargs):
                if delivery == 'bad': raise ValueError('sensitive-token')
                return 'sent'
            output = io.StringIO()
            with patch.object(o, 'publish_worker_result', side_effect=publish) as mock, contextlib.redirect_stdout(output):
                o.publication_loop(db, {}, Mock(), Mock(), '', '', '', Stop())
            self.assertEqual(output.getvalue().splitlines(), ['{"status": "publication_error"}', '{"status": "publication_sent"}'])
            self.assertEqual([c.args[1] for c in mock.call_args_list], ['bad', 'good', 'bad', 'bad'])

    def test_publication_thread_start_failure_stops_and_joins_notification(self):
        with tempfile.TemporaryDirectory() as root:
            db = os.path.join(root, 'queue')
            open(db, 'w').close()
            threads = []
            class Thread:
                def __init__(self, target, args):
                    self.args, self.joined = args, False
                    threads.append(self)
                def start(self):
                    if len(threads) == 2: raise RuntimeError('sensitive-token')
                def join(self): self.joined = True
            github = Mock(auth=Mock(app_id=1, installation_id=2, key_path='fake'))
            with patch.dict(os.environ, {'WEBHOOK_SECRET': 'fake', 'DISCORD_CHANNEL_ID': '123'}, clear=True), \
                 patch.object(o, 'require_app_read_flag'), patch.object(o, 'allowed', return_value={1466550689: 'juny0955/pr-review-bot'}), \
                 patch.object(o, 'DiscordTransport'), patch.object(o, 'DiscordNotifier'), \
                 patch.object(o, 'GitHubReadOnly', return_value=github), patch.object(o, 'app_read_auth'), \
                 patch.object(o, 'InstallationAuth'), patch.object(o, 'resolve_hermes_direct_adapter'), \
                 patch.object(o, 'Worker'), patch.object(o, 'Outbox'), patch.object(o.threading, 'Thread', Thread), \
                 patch.object(o.signal, 'signal'), contextlib.redirect_stdout(io.StringIO()) as output:
                result = o.main(['--db', db, '--wiki', root, '--repos', 'fake', '--enable-direct-inference',
                                 '--authorize-wiki-transfer', '--github-app-read', '--single-vps-publish',
                                 '--publication-ledger', root+'/ledger', '--publication-gate', root+'/gate',
                                 '--enable-discord-notifications'])
            self.assertEqual(result, 1)
            self.assertTrue(threads[0].args[-1].is_set())
            self.assertTrue(threads[0].joined)
            self.assertFalse(threads[1].joined)
            self.assertEqual(output.getvalue(), '{"status": "error"}\n')


if __name__ == '__main__': unittest.main()
