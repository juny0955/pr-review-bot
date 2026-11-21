import json
import unittest
from unittest.mock import patch

from github_adapter import GitHubReadOnly

SHA = 'a' * 40
REPO = 'example-owner/example-repo'


class AdapterTests(unittest.TestCase):
    def test_real_dedicated_mount_is_accepted(self):
        import os
        from github_adapter import _bounded_git_root
        if not os.path.isdir('/run/pr-review-bot-diff'):
            self.skipTest('dedicated production mount is not present')
        with patch.dict(os.environ, {'PR_DIFF_TMPDIR': '/run/pr-review-bot-diff'}):
            self.assertEqual(_bounded_git_root(), '/run/pr-review-bot-diff')

    def test_real_mount_rejects_excessive_filesystem_size(self):
        import os
        from types import SimpleNamespace
        from github_adapter import _bounded_git_root, MAX_GIT_STORAGE
        if not os.path.isdir('/run/pr-review-bot-diff'):
            self.skipTest('dedicated production mount is not present')
        with patch.dict(os.environ, {'PR_DIFF_TMPDIR': '/run/pr-review-bot-diff'}), \
             patch('github_adapter.os.fstatvfs', return_value=SimpleNamespace(f_blocks=2, f_frsize=MAX_GIT_STORAGE)) as fstatvfs:
            with self.assertRaisesRegex(RuntimeError, '^bounded git scratch unavailable$') as error:
                _bounded_git_root()
            self.assertIsInstance(error.exception.__cause__, ValueError)
            self.assertEqual(str(error.exception.__cause__), 'unbounded or non-tmpfs mount')
            fstatvfs.assert_called_once()

    def test_real_mount_rejects_non_tmpfs_and_fstatfs_failure(self):
        import os
        from unittest.mock import Mock
        from github_adapter import _bounded_git_root
        if not os.path.isdir('/run/pr-review-bot-diff'):
            self.skipTest('dedicated production mount is not present')
        with patch.dict(os.environ, {'PR_DIFF_TMPDIR': '/run/pr-review-bot-diff'}):
            for result in (0, -1):
                fstatfs = Mock(return_value=result)
                with self.subTest(result=result), patch('github_adapter.ctypes.CDLL', return_value=Mock(fstatfs=fstatfs)):
                    with self.assertRaisesRegex(RuntimeError, '^bounded git scratch unavailable$') as error:
                        _bounded_git_root()
                    fstatfs.assert_called_once()
                    if result == 0:
                        self.assertIsInstance(error.exception.__cause__, ValueError)
                        self.assertEqual(str(error.exception.__cause__), 'unbounded or non-tmpfs mount')
                    else:
                        self.assertIsInstance(error.exception.__cause__, OSError)
                        self.assertEqual(getattr(error.exception.__cause__, 'strerror', None), 'fstatfs failed')

    def test_real_mount_rejects_inode_mismatch(self):
        import os
        from types import SimpleNamespace
        from github_adapter import _bounded_git_root
        path = '/run/pr-review-bot-diff'
        if not os.path.isdir(path):
            self.skipTest('dedicated production mount is not present')
        real_lstat = os.lstat
        def changed(name):
            result = real_lstat(name)
            if name == path:
                return SimpleNamespace(st_dev=result.st_dev, st_ino=result.st_ino + 1)
            return result
        with patch.dict(os.environ, {'PR_DIFF_TMPDIR': path}), patch('github_adapter.os.lstat', side_effect=changed) as lstat:
            with self.assertRaisesRegex(RuntimeError, '^bounded git scratch unavailable$') as error:
                _bounded_git_root()
            self.assertIsInstance(error.exception.__cause__, ValueError)
            self.assertEqual(str(error.exception.__cause__), 'untrusted mount')
            lstat.assert_any_call(path)

    def test_pinned_diff_fails_closed_without_bounded_mount(self):
        import os
        from github_adapter import _pinned_diff
        with patch.dict(os.environ, {}, clear=True), patch('github_adapter.subprocess.Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'bounded'):
                _pinned_diff('remote', 1, SHA, 'b' * 40)
            popen.assert_not_called()

    def test_bounded_root_requires_small_tmpfs_mount(self):
        import ctypes
        import stat
        from contextlib import ExitStack
        from types import SimpleNamespace
        from unittest.mock import Mock
        from github_adapter import _bounded_git_root, MAX_GIT_STORAGE
        path = '/run/pr-review-bot-diff'
        parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        root = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=123, st_dev=1, st_ino=2)
        magic = [0x01021994]
        def fstatfs(fd, buf):
            ctypes.cast(buf, ctypes.POINTER(ctypes.c_long))[0] = magic[0]
            return 0
        with ExitStack() as stack:
            stack.enter_context(patch.dict('os.environ', {'PR_DIFF_TMPDIR': path}))
            stack.enter_context(patch('github_adapter.os.lstat', side_effect=lambda p: root if p == path else parent))
            stack.enter_context(patch('github_adapter.os.open', return_value=42))
            close = stack.enter_context(patch('github_adapter.os.close'))
            stack.enter_context(patch('github_adapter.os.fstat', return_value=root))
            stack.enter_context(patch('github_adapter.os.geteuid', return_value=123))
            ismount = stack.enter_context(patch('github_adapter.os.path.ismount', return_value=True))
            size = stack.enter_context(patch('github_adapter.os.fstatvfs', return_value=SimpleNamespace(f_blocks=1, f_frsize=MAX_GIT_STORAGE)))
            stack.enter_context(patch('github_adapter.ctypes.CDLL', return_value=Mock(fstatfs=fstatfs)))
            self.assertEqual(_bounded_git_root(), path)
            for blocks in (0, 2):
                with self.subTest(blocks=blocks):
                    size.return_value = SimpleNamespace(f_blocks=blocks, f_frsize=MAX_GIT_STORAGE)
                    with self.assertRaisesRegex(RuntimeError, '^bounded git scratch unavailable$') as error:
                        _bounded_git_root()
                    self.assertEqual(str(error.exception.__cause__), 'unbounded or non-tmpfs mount')
            size.return_value = SimpleNamespace(f_blocks=1, f_frsize=4096)
            magic[0] = 0xEF53
            with self.assertRaisesRegex(RuntimeError, '^bounded git scratch unavailable$') as error:
                _bounded_git_root()
            self.assertEqual(str(error.exception.__cause__), 'unbounded or non-tmpfs mount')
            magic[0] = 0x01021994
            ismount.return_value = False
            with self.assertRaisesRegex(RuntimeError, '^bounded git scratch unavailable$') as error:
                _bounded_git_root()
            self.assertEqual(str(error.exception.__cause__), 'untrusted mount')
            self.assertEqual(close.call_count, 5)

    def test_git_process_starts_without_preexec_fn(self):
        from github_adapter import _pinned_diff
        with patch('github_adapter._bounded_git_root', return_value='/dev/shm'), \
             patch('github_adapter.subprocess.Popen', side_effect=OSError('stop')) as popen:
            with self.assertRaises(OSError):
                _pinned_diff('remote', 1, SHA, 'b' * 40)
            self.assertNotIn('preexec_fn', popen.call_args.kwargs)
            self.assertTrue(popen.call_args.kwargs.get('start_new_session'))

    def test_git_child_group_is_killed_on_wait_exception(self):
        from unittest.mock import Mock
        from github_adapter import _pinned_diff
        proc = Mock(pid=12345)
        proc.wait.side_effect = [RuntimeError('interrupted'), 0]
        with patch('github_adapter._bounded_git_root', return_value='/dev/shm'), \
             patch('github_adapter.subprocess.Popen', return_value=proc), \
             patch('github_adapter.os.killpg') as killpg:
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                _pinned_diff('remote', 1, SHA, 'b' * 40)
            killpg.assert_called_once()
            self.assertEqual(proc.wait.call_count, 2)

    def test_pinned_git_receives_only_explicit_gh_token_environment(self):
        import os
        from github_adapter import _pinned_diff
        with patch.dict(os.environ, {'GH_TOKEN': 'secret-one', 'GITHUB_TOKEN': 'secret-two',
                                     'UNSAFE_SECRET': 'do-not-forward'}, clear=True), \
             patch('github_adapter._bounded_git_root', return_value='/dev/shm'), \
             patch('github_adapter.subprocess.Popen', side_effect=OSError('stop')) as popen:
            with self.assertRaises(OSError):
                _pinned_diff('remote', 1, SHA, 'b' * 40)
            env = popen.call_args.kwargs['env']
            self.assertEqual(env['GH_TOKEN'], 'secret-one')
            self.assertEqual(env['GITHUB_TOKEN'], 'secret-two')
            self.assertNotIn('UNSAFE_SECRET', env)

    def test_readonly_current_supplies_publisher_verified_identity(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import Mock
        from publisher import GitHubPublisher
        pr = json.dumps({'state': 'open', 'draft': False, 'head': {'sha': SHA},
                         'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': REPO}}}).encode()
        # Exercise the dormant publisher path with fake transports only.
        with tempfile.TemporaryDirectory() as directory, patch('github_adapter._gh_get', return_value=pr), \
             patch('publisher._require_revocation_gate'):
            post = Mock()
            publisher = GitHubPublisher(post, GitHubReadOnly({123: REPO}).current, {123: REPO},
                                        enabled=True, ledger_path=Path(directory) / 'ledger', get=Mock())
            self.assertEqual(publisher.publish(123, REPO, 1, SHA, 'review', base_sha='b' * 40), 'sent')
            post.assert_called_once()

    def test_pinned_diff_uses_merge_base_and_pr_head(self):
        import subprocess
        import tempfile
        from pathlib import Path
        from github_adapter import _pinned_diff
        import os
        if not os.path.isdir('/run/pr-review-bot-diff'):
            self.skipTest('dedicated production mount is not present')
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'PR_DIFF_TMPDIR': '/run/pr-review-bot-diff'}):
            def git(*args):
                return subprocess.check_output(['git', '-C', d, *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q', '-b', 'master')
            git('config', 'user.email', 'test@example.com')
            git('config', 'user.name', 'Test')
            Path(d, 'file').write_text('root\n')
            git('add', 'file'); git('commit', '-qm', 'root')
            git('checkout', '-qb', 'feature')
            Path(d, 'file').write_text('root\nfeature\n')
            git('commit', '-qam', 'feature')
            head = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/pull/1/head', head)
            git('checkout', '-q', 'master')
            Path(d, 'base').write_text('base\n')
            git('add', 'base'); git('commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD')
            diff = _pinned_diff(d, 1, head, base)
            self.assertIn('+feature', diff)
            self.assertNotIn('base\n', diff)
            with self.assertRaises(ValueError):
                _pinned_diff(d, 1, 'a' * 40, base)

    def test_diff_uses_verified_pins_not_mutable_diff_endpoint(self):
        gh = GitHubReadOnly({123: REPO})
        current = {'state': 'open', 'draft': False, 'sha': SHA, 'base_sha': 'b' * 40}
        with patch.object(gh, 'current', return_value=current), \
             patch('github_adapter._gh_get') as get, \
             patch('github_adapter._pinned_diff', return_value='pinned') as diff:
            self.assertEqual(gh.diff(REPO, 1, SHA, 'b' * 40), 'pinned')
            diff.assert_called_once_with('https://github.com/' + REPO + '.git', 1, SHA, 'b' * 40)
            get.assert_not_called()

    def test_current_reads_pr_metadata(self):
        pr = json.dumps({'state': 'open', 'draft': False, 'head': {'sha': SHA}, 'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': REPO}}}).encode()
        with patch('github_adapter._gh_get', return_value=pr) as get:
            gh = GitHubReadOnly({123: REPO})
            self.assertEqual(gh.current(REPO, 1)['sha'], SHA)
            self.assertEqual(get.call_args.args[0], 'repos/example-owner/example-repo/pulls/1')

    def test_rejects_invalid_inputs_before_network(self):
        gh = GitHubReadOnly({123: REPO})
        with patch('github_adapter._gh_get') as get:
            for repo, number, sha in [('evil/repo', 1, SHA), (REPO, True, SHA), (REPO, 1, 'bad')]:
                with self.subTest(repo=repo, number=number, sha=sha), self.assertRaises(ValueError):
                    gh.diff(repo, number, sha, 'b' * 40)
            get.assert_not_called()

    def test_diff_rejects_stale_and_draft(self):
        gh = GitHubReadOnly({123: REPO})
        for state in ({'state': 'open', 'draft': True, 'sha': SHA},
                      {'state': 'open', 'draft': False, 'sha': 'b' * 40}):
            with self.subTest(state=state), patch.object(gh, 'current', return_value=state), patch('github_adapter._gh_get') as get:
                with self.assertRaises(ValueError):
                    gh.diff(REPO, 1, SHA, 'b' * 40)
                get.assert_not_called()

    def test_gh_process_is_get_and_caps_output(self):
        import io
        import os
        from github_adapter import _gh_get
        class Process:
            def __init__(self, data):
                read, write = os.pipe()
                os.write(write, data)
                os.close(write)
                self.stdout = os.fdopen(read, 'rb')
                self.killed = False
            def poll(self):
                return None if not self.killed else -9
            def kill(self):
                self.killed = True
            def wait(self, timeout=None):
                return 0
        proc = Process(b'12345')
        with patch('github_adapter.subprocess.Popen', return_value=proc) as popen:
            with self.assertRaises(ValueError):
                _gh_get('repos/x/y/pulls/1', 'application/vnd.github+json', 4)
            args, kwargs = popen.call_args
            self.assertIn('GET', args[0])
            self.assertEqual(args[0][0:3], ['gh', 'api', '--hostname'])
            self.assertNotIn('shell', kwargs)
            self.assertTrue(proc.killed)


if __name__ == '__main__':
    unittest.main()
