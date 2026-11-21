import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from repo_config import allowed
from github_adapter import GitHubReadOnly

class RepoConfigTests(unittest.TestCase):
    def test_durable_rename_and_disable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'repos.json'
            def write(name, enabled=True):
                path.write_text(json.dumps({'repositories': [{'id': 42, 'full_name': name, 'enabled': enabled}]}))
            write('old/name')
            self.assertEqual(allowed(path), {42: 'old/name'})
            write('new/name')
            self.assertEqual(allowed(path), {42: 'new/name'})
            write('new/name', False)
            self.assertEqual(allowed(path), {})

    def test_malformed_and_duplicates_fail_closed(self):
        for value in ({True: 'a/b'}, {1: '../b'}, {1: 'a/b', 2: 'A/B'}, {0: 'a/b'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                allowed(value)

    def test_api_rejects_reused_name_with_different_id(self):
        gh = GitHubReadOnly({42: 'new/name'})
        response = {'state': 'open', 'draft': False, 'head': {'sha': 'a'*40}, 'base': {'sha': 'b'*40, 'repo': {'id': 43, 'full_name': 'new/name'}}}
        with patch('github_adapter._gh_get', return_value=json.dumps(response).encode()):
            with self.assertRaises(ValueError):
                gh.current('new/name', 1)
