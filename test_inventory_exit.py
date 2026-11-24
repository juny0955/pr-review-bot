import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import orchestrator


class InventoryExitTest(unittest.TestCase):
    def test_broken_status_still_stops_and_marks_failure(self):
        import threading
        stop, failed = threading.Event(), threading.Event()
        with patch.object(orchestrator, 'reconcile_installation', side_effect=RuntimeError()), \
             patch.object(orchestrator, '_status', side_effect=BrokenPipeError()):
            orchestrator.inventory_loop(None, None, None, stop, poll_interval=0, failed=failed)
        self.assertTrue(failed.is_set())
        self.assertTrue(stop.is_set())

    def test_periodic_failure_exits_nonzero_after_successful_start(self):
        with tempfile.TemporaryDirectory() as root:
            db = Path(root) / 'queue.db'
            db.touch()
            args = ['--db', str(db), '--wiki', root, '--repos', root,
                    '--dry-run', '--enable-direct-inference', '--authorize-wiki-transfer',
                    '--github-app-read', '--publication-gate', root, '--sync-installation']
            inventory_loop = orchestrator.inventory_loop
            def fast_inventory(*args, **kwargs):
                return inventory_loop(*args, poll_interval=0, **kwargs)
            def run(worker, stop):
                self.assertTrue(stop.wait(2))
            output = io.StringIO()
            with patch.dict(os.environ, {'WEBHOOK_SECRET': 'secret'}), \
                 patch.object(orchestrator, 'allowed', return_value={}), \
                 patch.object(orchestrator, 'require_app_read_flag'), \
                 patch.object(orchestrator, 'app_read_auth'), \
                 patch.object(orchestrator, 'GitHubReadOnly', return_value=Mock(auth=Mock())), \
                 patch.object(orchestrator, 'reconcile_installation', side_effect=[None, RuntimeError('private')]), \
                 patch.object(orchestrator, 'resolve_hermes_direct_adapter'), \
                 patch.object(orchestrator, 'Worker'), \
                 patch.object(orchestrator, 'inventory_loop', side_effect=fast_inventory), \
                 patch.object(orchestrator, 'run_loop', side_effect=run), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(orchestrator.main(args), 1)
            self.assertEqual(output.getvalue(), '{"status": "inventory_error", "stage": "inventory", "exception": "RuntimeError"}\n')


if __name__ == '__main__':
    unittest.main()
