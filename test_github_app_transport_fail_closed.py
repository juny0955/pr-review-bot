import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import unittest
from unittest.mock import patch, Mock

from github_app_transport import installation_transport, read_transport, MAX_RESPONSE


class FailClosedTests(unittest.TestCase):
    def test_cleanup_failure_overrides_success_without_leaking(self):
        original = subprocess.Popen
        def launch(args, **kwargs):
            return original([sys.executable, '-c',
                             'import sys; sys.stdin.buffer.read(); sys.stdout.write("{}")'], **kwargs)
        with patch('github_app_transport.subprocess.Popen', side_effect=launch), \
             patch('github_app_transport.os.killpg', side_effect=PermissionError('secret')):
            with self.assertRaisesRegex(RuntimeError, '^GitHub transport failed$') as error:
                installation_transport('fake-secret', 1, {})
            self.assertIsNone(error.exception.__context__)

    def test_full_output_pipe_and_unread_input_do_not_deadlock(self):
        original = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            child = original([sys.executable, '-c',
                              'import os,time; os.write(1, b"x" * 1000000); time.sleep(60)'], **kwargs)
            children.append(child)
            return child
        with patch('github_app_transport.subprocess.Popen', side_effect=launch), \
             patch('github_app_transport.TIMEOUT', 0.3):
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, '^GitHub transport failed$'):
                installation_transport('fake-secret', 1, {'data': 'x' * 7000})
            self.assertLess(time.monotonic() - started, 3)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdin.closed and children[0].stdout.closed)

    def test_failed_kills_do_not_cause_unbounded_wait(self):
        original = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            child = original([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
            children.append(child)
            child.kill = Mock(side_effect=PermissionError('secret'))
            return child
        try:
            with patch('github_app_transport.subprocess.Popen', side_effect=launch), \
                 patch('github_app_transport.os.killpg', side_effect=PermissionError('secret')), \
                 patch('github_app_transport.TIMEOUT', 0.15):
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, '^GitHub transport failed$') as error:
                    installation_transport('fake-secret', 1, {})
                self.assertLess(time.monotonic() - started, 3)
            self.assertIsNone(error.exception.__context__)
            self.assertTrue(children[0].stdin.closed and children[0].stdout.closed)
            children[0].kill.assert_called_once()
        finally:
            if children:
                subprocess.Popen.kill(children[0])
                subprocess.Popen.wait(children[0], timeout=3)

    def test_killpg_permission_error_still_kills_closes_and_waits(self):
        original = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            child = original([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
            child.wait = Mock(wraps=child.wait)
            children.append(child)
            return child
        try:
            with patch('github_app_transport.subprocess.Popen', side_effect=launch), \
                 patch('github_app_transport.os.killpg', side_effect=PermissionError('secret')), \
                 patch('github_app_transport.TIMEOUT', 0.15):
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, '^GitHub transport failed$') as error:
                    installation_transport('fake-secret', 1, {})
                self.assertLess(time.monotonic() - started, 3)
            self.assertIsNone(error.exception.__context__)
            self.assertEqual(children[0].returncode, -signal.SIGKILL)
            self.assertTrue(children[0].stdin.closed)
            self.assertTrue(children[0].stdout.closed)
            children[0].wait.assert_called()
        finally:
            if children and children[0].poll() is None:
                children[0].kill()
                children[0].wait()

    def test_cleanup_continues_after_close_failure_and_wait_is_bounded(self):
        original = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            child = original([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
            children.append(child)
            child._test_close = child.stdin.close
            child.stdin.close = Mock(side_effect=OSError('secret'))
            child.wait = Mock(side_effect=subprocess.TimeoutExpired('secret', 1))
            return child
        try:
            with patch('github_app_transport.subprocess.Popen', side_effect=launch), \
                 patch('github_app_transport.TIMEOUT', 0.15):
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, '^GitHub transport failed$') as error:
                    installation_transport('fake-secret', 1, {})
                self.assertLess(time.monotonic() - started, 3)
            self.assertIsNone(error.exception.__context__)
            self.assertTrue(children[0].stdout.closed)
            children[0].wait.assert_called_once()
            self.assertIsNotNone(children[0].wait.call_args.kwargs.get('timeout'))
        finally:
            if children:
                children[0]._test_close()
                subprocess.Popen.wait(children[0], timeout=3)

    def run_child(self, script, call):
        original = subprocess.Popen
        children = []
        def launch(args, **kwargs):
            self.assertNotIn('fake-secret', repr((args, kwargs.get('env'))))
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertTrue(kwargs['start_new_session'])
            child = original([sys.executable, '-c', script], **kwargs)
            children.append(child)
            return child
        with patch('github_app_transport.subprocess.Popen', side_effect=launch):
            result = call()
        self.assertIsNotNone(children[0].returncode)
        return result

    def test_private_pipe_and_response(self):
        script = "import json,sys; x=json.load(sys.stdin); assert x['credential']=='fake-secret'; assert x['path']=='/repos/o/r/pulls/1'; sys.stdout.write('{\"ok\":true}')"
        self.assertEqual(self.run_child(script, lambda: read_transport('fake-secret', '/repos/o/r/pulls/1')), {'ok': True})

    def test_oversized_or_invalid_stdout_fails_safely(self):
        for script in (f"import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'x'*{MAX_RESPONSE + 1})",
                       "import sys; sys.stdin.buffer.read(); sys.stdout.write('fake-secret')"):
            with self.subTest(script=script):
                def call():
                    with self.assertRaisesRegex(RuntimeError, '^GitHub transport failed$') as error:
                        installation_transport('fake-secret', 1, {})
                    self.assertIsNone(error.exception.__context__)
                self.run_child(script, call)

    def test_timeout_kills_process_group(self):
        original = subprocess.Popen
        children = []
        script = "import os,sys,time; p=os.fork(); sys.stdin.buffer.read() if p else None; time.sleep(60)"
        def launch(args, **kwargs):
            child = original([sys.executable, '-c', script], **kwargs)
            children.append(child)
            return child
        with patch('github_app_transport.subprocess.Popen', side_effect=launch), patch('github_app_transport.TIMEOUT', 0.3):
            with self.assertRaises(RuntimeError):
                installation_transport('fake-secret', 1, {})
        self.assertEqual(children[0].returncode, -signal.SIGKILL)
        # Descendants can briefly remain as zombies; they must not remain running.
        for pid in os.listdir('/proc'):
            if pid.isdigit():
                try:
                    stat = Path('/proc', pid, 'stat').read_text().rsplit(')', 1)[1].split()
                    if int(stat[2]) == children[0].pid:
                        self.assertEqual(stat[0], 'Z')
                except (FileNotFoundError, ProcessLookupError):
                    pass


if __name__ == '__main__':
    unittest.main()
