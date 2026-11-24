import contextlib
import io
import json
import sqlite3
import threading
import unittest
from unittest.mock import Mock, patch

import orchestrator


class ErrorDiagnosticsTest(unittest.TestCase):
    def test_inventory_logs_only_fixed_stage_and_class(self):
        class PrivateTokenError(ValueError):
            pass
        for error, expected in [(RuntimeError('https://secret/token'), 'RuntimeError'),
                                (PrivateTokenError('secret'), 'other')]:
            stop = threading.Event()
            output = io.StringIO()
            with patch.object(orchestrator, 'reconcile_installation', side_effect=error), contextlib.redirect_stdout(output):
                orchestrator.inventory_loop(None, None, None, stop, poll_interval=0)
            self.assertEqual(json.loads(output.getvalue()), {'status': 'inventory_error', 'stage': 'inventory', 'exception': expected})
            self.assertTrue(stop.is_set())

    def test_publication_poll_and_job_failures_are_distinct_and_safe(self):
        class PrivateTokenError(Exception):
            pass
        class Stop:
            count = 0
            def is_set(self): return self.count >= 2
            def wait(self, _): self.count += 1
        conn = Mock()
        conn.execute.return_value = [('private-delivery',)]
        output = io.StringIO()
        with patch.object(orchestrator.sqlite3, 'connect', side_effect=[sqlite3.OperationalError('secret'), conn]), \
             patch.object(orchestrator, 'publish_worker_result', side_effect=PrivateTokenError('secret')), \
             contextlib.redirect_stdout(output):
            orchestrator.publication_loop('fake', {}, Mock(), Mock(), '', '', '', Stop())
        self.assertEqual([json.loads(line) for line in output.getvalue().splitlines()], [
            {'status': 'publication_error', 'stage': 'poll', 'exception': 'OperationalError'},
            {'status': 'publication_error', 'stage': 'job', 'exception': 'other'},
        ])


if __name__ == '__main__':
    unittest.main()
