import contextlib
import io
import sqlite3
import unittest
from unittest.mock import Mock, patch

import orchestrator


class PublicationPollErrorsTest(unittest.TestCase):
    def test_database_failure_recovery_and_job_error_are_independent(self):
        class Stop:
            count = 0
            def is_set(self): return self.count >= 7
            def wait(self, _): self.count += 1

        conn = Mock()
        conn.execute.return_value = [('bad',)]
        connect = [sqlite3.OperationalError('secret')] * 3 + [conn] + [sqlite3.OperationalError('secret')] * 2 + [conn]
        output = io.StringIO()
        with patch.object(orchestrator.sqlite3, 'connect', side_effect=connect), \
             patch.object(orchestrator, 'publish_worker_result', side_effect=ValueError('secret')) as publish, \
             contextlib.redirect_stdout(output):
            orchestrator.publication_loop('fake', {}, Mock(), Mock(), '', '', '', Stop())
        self.assertEqual(output.getvalue().splitlines(), ['{"status": "publication_error"}'] * 3)
        self.assertEqual(publish.call_count, 2)


if __name__ == '__main__':
    unittest.main()
