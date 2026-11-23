import unittest
from installation_inventory import public_snapshot, installation_snapshot
from github_app_transport import inventory_transport
from unittest.mock import patch


def repo(ident, name, private=False):
    return {'id': ident, 'full_name': name, 'private': private}


class InventoryTests(unittest.TestCase):
    def test_complete_paginated_snapshot_and_private_exclusion(self):
        entries = [repo(i, f'owner/r{i}', i == 2) for i in range(1, 102)]
        calls = []
        def fetch(page, size):
            calls.append(page)
            return {'total_count': len(entries), 'repositories': entries[(page - 1)*size:page*size]}
        result = public_snapshot(fetch)
        self.assertEqual(len(result), 100)
        self.assertNotIn(2, result)
        self.assertEqual(calls, [1, 2, 1, 2])

    def test_installation_transport_paginates_and_fails_closed(self):
        entries = [repo(i, f'a/r{i}', i == 101) for i in range(1, 102)]
        calls = []
        def fake(token, path):
            calls.append((token, path))
            page = int(path.rsplit('=', 1)[1])
            return {'total_count': len(entries), 'repositories': entries[(page-1)*100:page*100]}
        result = installation_snapshot(fake, 'synthetic')
        self.assertEqual(len(result), 100)
        self.assertNotIn(101, result)
        self.assertEqual([p.rsplit('=', 1)[1] for _, p in calls], ['1', '2', '1', '2'])
        with patch('github_app_transport._request', return_value={'total_count': 0, 'repositories': []}) as request:
            self.assertEqual(installation_snapshot(inventory_transport, 'synthetic'), {})
            self.assertEqual(request.call_count, 2)
            with self.assertRaises(RuntimeError):
                inventory_transport('synthetic', '/installation/repositories?per_page=100&page=1001')
            self.assertEqual(request.call_count, 2)

    def test_empty(self):
        self.assertEqual(public_snapshot(lambda page, size: {'total_count': 0, 'repositories': []}), {})

    def test_partial_and_unstable_snapshots_rejected(self):
        cases = [
            lambda page, size: {'total_count': 1, 'repositories': []},
            lambda page, size: {'total_count': 2, 'repositories': [repo(1, 'a/b'), repo(1, 'a/c')]},
            lambda page, size: {'total_count': 1, 'repositories': [repo(1, '../b')]},
            lambda page, size: {'total_count': 1, 'repositories': [{'id': 1, 'full_name': 'a/b'}]},
        ]
        for fetch in cases:
            with self.subTest(fetch=fetch), self.assertRaises(ValueError):
                public_snapshot(fetch)
        count = iter([repo(1, 'a/b'), repo(1, 'a/c')])
        with self.assertRaises(ValueError):
            public_snapshot(lambda page, size: {'total_count': 1, 'repositories': [next(count)]})

    def test_fetch_failure_propagates(self):
        def fetch(page, size):
            if page == 2:
                raise RuntimeError('unavailable')
            return {'total_count': 101, 'repositories': [repo(i, f'a/r{i}') for i in range(1, 101)]}
        with self.assertRaises(RuntimeError):
            public_snapshot(fetch)


if __name__ == '__main__':
    unittest.main()
