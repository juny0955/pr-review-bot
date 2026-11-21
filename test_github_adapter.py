import json
import unittest
from unittest.mock import patch

from github_adapter import GitHubReadOnly

SHA = 'a' * 40
REPO = 'example-owner/example-repo'


class AdapterTests(unittest.TestCase):
    def test_readonly_current_supplies_publisher_verified_identity(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import Mock
        from publisher import GitHubPublisher
        pr = json.dumps({'state': 'open', 'draft': False, 'head': {'sha': SHA},
                         'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': REPO}}}).encode()
        with tempfile.TemporaryDirectory() as directory, patch('github_adapter._gh_get', return_value=pr):
            post = Mock()
            publisher = GitHubPublisher(post, GitHubReadOnly({123: REPO}).current, {123: REPO},
                                        enabled=True, ledger_path=Path(directory) / 'ledger', get=Mock())
            self.assertEqual(publisher.publish(123, REPO, 1, SHA, 'review', base_sha='b' * 40), 'sent')
            post.assert_called_once()

    def test_diff_fails_closed_without_fetching_mutable_pr_diff(self):
        gh = GitHubReadOnly({123: REPO})
        current = {'state': 'open', 'draft': False, 'sha': SHA, 'base_sha': 'b' * 40}
        with patch.object(gh, 'current', return_value=current), patch('github_adapter._gh_get') as get:
            with self.assertRaisesRegex(RuntimeError, 'immutable'):
                gh.diff(REPO, 1, SHA, 'b' * 40)
            get.assert_not_called()

    def test_current_and_diff_use_read_only_get_and_check_sha(self):
        pr = json.dumps({'state': 'open', 'draft': False, 'head': {'sha': SHA}, 'base': {'sha': 'b' * 40, 'repo': {'id': 123, 'full_name': REPO}}}).encode()
        with patch('github_adapter._gh_get', side_effect=[pr, pr, b'diff text', pr]) as get:
            gh = GitHubReadOnly({123: REPO})
            self.assertEqual(gh.current(REPO, 1)['sha'], SHA)
            with self.assertRaisesRegex(RuntimeError, 'immutable'):
                gh.diff(REPO, 1, SHA, 'b' * 40)
            self.assertTrue(all(call.args[0] == 'repos/example-owner/example-repo/pulls/1' for call in get.call_args_list))

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
