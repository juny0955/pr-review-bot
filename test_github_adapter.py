import json
import unittest
from unittest.mock import patch

from github_adapter import GitHubReadOnly

SHA = 'a' * 40
REPO = 'example-owner/example-repo'


class AdapterTests(unittest.TestCase):
    def test_current_rejects_missing_or_mismatched_pr_number(self):
        from unittest.mock import Mock
        pr = {'number': 1, 'state': 'open', 'draft': False, 'head': {'sha': SHA},
              'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': REPO, 'private': False}}}
        for auth in (None, Mock(permission='read', token=Mock(return_value=('fake', 0)))):
            for number in (None, True, '1', 2, 1):
                response = dict(pr)
                if number is None:
                    del response['number']
                else:
                    response['number'] = number
                with self.subTest(app=auth is not None, number=number), \
                     patch('github_adapter._gh_get', return_value=json.dumps(response).encode()), \
                     patch('github_adapter.read_transport', return_value=response):
                    adapter = GitHubReadOnly({123: REPO}, auth=auth)
                    if type(number) is int and number == 1:
                        self.assertEqual(adapter.current(REPO, 1)['sha'], SHA)
                    else:
                        with self.assertRaises(ValueError):
                            adapter.current(REPO, 1)

    def test_app_diff_checks_identity_and_state_before_and_after_fetch(self):
        from unittest.mock import Mock
        auth = Mock(permission='read', token=Mock(return_value=('fake-token', 0)))
        adapter = GitHubReadOnly({123: REPO}, auth=auth)
        pr = {'number': 1, 'state': 'open', 'draft': False, 'head': {'sha': SHA},
              'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': REPO, 'private': False}}}
        with patch('github_adapter._pinned_diff', return_value='diff') as git, \
             patch('github_adapter._gh_get') as gh, \
             patch('github_adapter.read_transport', return_value=pr) as transport:
            self.assertEqual(adapter.diff(REPO, 1, SHA, 'b' * 40), 'diff')
            self.assertEqual(transport.call_count, 2)
            git.assert_called_once_with('https://github.com/' + REPO + '.git', 1, SHA, 'b' * 40, public_only=True)
            self.assertEqual(auth.token.call_count, 2)
            gh.assert_not_called()
            for changed in (dict(pr, state='closed'), dict(pr, draft=True),
                            dict(pr, head={'sha': 'c' * 40}),
                            dict(pr, base={'sha': 'b' * 40, 'repo': {'id': 124, 'full_name': REPO}})):
                transport.side_effect = [pr, changed]
                with self.assertRaises(ValueError):
                    adapter.diff(REPO, 1, SHA, 'b' * 40)

    def test_app_git_credentials_are_isolated_and_redirects_disabled(self):
        import os
        from github_adapter import _pinned_diff
        with patch.dict(os.environ, {'GH_TOKEN': 'ambient', 'GITHUB_TOKEN': 'ambient', 'HTTPS_PROXY': 'http://evil',
                                     'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'http.extraheader'}, clear=True), \
             patch('github_adapter._bounded_git_root', return_value='/dev/shm'), \
             patch('github_adapter.subprocess.Popen', side_effect=OSError('stop')) as popen:
            with self.assertRaises(OSError):
                _pinned_diff('https://github.com/' + REPO + '.git', 1, SHA, 'b' * 40, public_only=True)
            args, env = popen.call_args.args[0], popen.call_args.kwargs['env']
            self.assertIn('http.followRedirects=false', args)
            self.assertNotIn('credential.helper=!gh auth git-credential', args)
            self.assertNotIn('fake-token', ' '.join(args))
            self.assertNotIn('GH_TOKEN', env)
            self.assertNotIn('GITHUB_TOKEN', env)
            for name in ('GH_CONFIG_DIR', 'HTTPS_PROXY', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0'):
                self.assertNotIn(name, env)
            self.assertEqual(env['GIT_CONFIG_NOSYSTEM'], '1')
            self.assertIn('credential.helper=', args)

    def test_app_public_only_fails_closed_and_rechecks_visibility(self):
        from unittest.mock import Mock
        auth = Mock(permission='read', token=Mock(return_value=('fake-token', 0)))
        adapter = GitHubReadOnly({123: REPO}, auth=auth)
        repo = {'id': 123, 'full_name': REPO, 'private': False}
        pr = {'number': 1, 'state': 'open', 'draft': False, 'head': {'sha': SHA},
              'base': {'sha': 'b' * 40, 'repo': repo}}
        with patch('github_adapter.read_transport') as transport, patch('github_adapter._pinned_diff') as git:
            for value in (True, None, 0, 'false'):
                transport.return_value = dict(pr, base={'sha': 'b' * 40, 'repo': dict(repo, private=value)})
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'public repository'):
                    adapter.diff(REPO, 1, SHA, 'b' * 40)
                git.assert_not_called()
            changed = dict(pr, base={'sha': 'b' * 40, 'repo': dict(repo, private=True)})
            transport.side_effect = [pr, changed]
            with self.assertRaisesRegex(ValueError, 'changed during fetch'):
                adapter.diff(REPO, 1, SHA, 'b' * 40)

    def test_public_git_synthetic_local_fetch_all_children_isolated(self):
        import base64
        import os
        import subprocess
        import tempfile
        from github_adapter import _pinned_diff
        with tempfile.TemporaryDirectory() as d:
            env = {'PATH': os.defpath, 'HOME': d, 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
                   'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid'}
            def git(*args, data=None):
                return subprocess.check_output(['git', '-C', d, *args], input=data, env=env, stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q')
            blob = git('hash-object', '-w', '--stdin', data=b'root\n')
            tree = git('mktree', data=f'100644 blob {blob}\tfile\n'.encode())
            base = git('commit-tree', tree, data=b'base\n')
            blob = git('hash-object', '-w', '--stdin', data=b'root\nfeature\n')
            tree = git('mktree', data=f'100644 blob {blob}\tfile\n'.encode())
            head = git('commit-tree', tree, '-p', base, data=b'head\n')
            git('update-ref', 'refs/pull/1/head', head)
            original = subprocess.Popen
            calls = []
            def launch(*args, **kwargs):
                calls.append((args[0], kwargs['env'].copy()))
                return original(*args, **kwargs)
            with patch.dict(os.environ, {'GH_TOKEN': 'fake-token', 'HTTPS_PROXY': 'http://invalid',
                                         'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'http.extraheader',
                                         'GIT_CONFIG_VALUE_0': 'secret'}, clear=True), \
                 patch('github_adapter._bounded_git_root', return_value='/dev/shm'), \
                 patch('github_adapter.subprocess.Popen', side_effect=launch):
                result = _pinned_diff(d, 1, head, base, public_only=True)
            self.assertIn('+feature', result)
            self.assertGreaterEqual(len(calls), 6)
            for args, child_env in calls:
                self.assertNotIn('fake-token', str((args, child_env)))
                self.assertNotIn(base64.b64encode(b'x-access-token:fake-token').decode(), str((args, child_env)))
                self.assertNotIn('HTTPS_PROXY', child_env)
                self.assertNotIn('GIT_CONFIG_COUNT', child_env)
                self.assertNotIn('GH_CONFIG_DIR', child_env)
                self.assertNotIn('credential.helper=!gh auth git-credential', args)
                self.assertIn('http.followRedirects=false', args)

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
        pr = json.dumps({'number': 1, 'state': 'open', 'draft': False, 'head': {'sha': SHA},
                         'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': REPO, 'private': False}}}).encode()
        # Exercise the dormant publisher path with fake transports only.
        with tempfile.TemporaryDirectory() as directory, patch('github_adapter._gh_get', return_value=pr), \
             patch('publisher._require_revocation_gate'), patch('publisher._require_operational_isolation'):
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
        pr = json.dumps({'number': 1, 'state': 'open', 'draft': False, 'head': {'sha': SHA}, 'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': REPO, 'private': False}}}).encode()
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
