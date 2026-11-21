from contextlib import closing
import hashlib
import hmac
import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

def payload(**changes):
    value = {'repository': {'id': 123, 'full_name': 'acme/repo'}, 'action': 'opened',
             'number': 1, 'pull_request': {'number': 1, 'draft': False,
                                            'state': 'open', 'head': {'sha': 'a' * 40}}}
    value.update(changes)
    return json.dumps(value).encode()

class ReceiverTest(unittest.TestCase):
    def test_signed_delivery_is_durable_and_deduplicated(self):
        from receiver import create_server
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / 'queue.db')
            server = create_server('secret', {123: 'acme/repo'}, db, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = payload()
                signature = 'sha256=' + hmac.new(b'secret', body, hashlib.sha256).hexdigest()
                headers = {'X-Hub-Signature-256': signature, 'X-GitHub-Event': 'pull_request', 'X-GitHub-Delivery': 'delivery-1'}
                def send(data, h):
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                    conn.request('POST', '/webhook', data, h)
                    response = conn.getresponse(); response.read(); conn.close()
                    return response.status
                self.assertEqual(send(body, headers), 202)
                self.assertEqual(send(body, headers), 200)
                with closing(sqlite3.connect(db)) as conn, conn:
                    self.assertEqual(conn.execute('SELECT delivery_id, body FROM queue').fetchall(), [('delivery-1', body)])
            finally:
                server.shutdown(); server.server_close(); thread.join()

class SecurityTest(unittest.TestCase):
    def setUp(self):
        from receiver import create_server
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / 'queue.db')
        self.server = create_server('secret', {123: 'acme/repo'}, self.db, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.tmp.cleanup()

    def send(self, body=None, overrides=None):
        if body is None: body = payload()
        headers = {'X-Hub-Signature-256': 'sha256=' + hmac.new(b'secret', body, hashlib.sha256).hexdigest(), 'X-GitHub-Event': 'pull_request', 'X-GitHub-Delivery': 'test-id'}
        headers.update(overrides or {})
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        conn.request('POST', '/webhook', body, headers)
        response = conn.getresponse(); response.read(); conn.close()
        return response.status

    def test_rejects_name_spoof_and_accepts_matching_identity(self):
        self.assertEqual(self.send(payload(repository={'id': 999, 'full_name': 'acme/repo'})), 403)
        self.assertEqual(self.send(payload(repository={'id': 123, 'full_name': 'evil/repo'})), 403)
        self.assertEqual(self.send(), 202)

    def test_rejects_bad_signature_and_body_tampering(self):
        self.assertEqual(self.send(overrides={'X-Hub-Signature-256': 'sha256=' + '0' * 64}), 401)
        self.assertEqual(self.send(overrides={'X-Hub-Signature-256': 'sha1=abc'}), 401)

    def test_rejects_unauthorized_repo_and_wrong_event(self):
        self.assertEqual(self.send(b'{"repository":{"full_name":"evil/repo"}}'), 403)
        self.assertEqual(self.send(overrides={'X-GitHub-Event': 'push'}), 400)

    def test_rejects_bad_json_and_invalid_delivery(self):
        self.assertEqual(self.send(b'['), 400)
        self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'bad id'}), 400)

    def test_delivery_conflict_does_not_replace_original(self):
        self.assertEqual(self.send(), 202)
        self.assertEqual(self.send(payload(action='reopened')), 409)
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 1)

    def test_replay_with_new_delivery_id_is_not_enqueued(self):
        self.assertEqual(self.send(), 202)
        self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'other-id'}), 200)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 1)

    def test_rejects_malformed_pr_fields(self):
        invalid = [payload(action='changed'), payload(action=[]), payload(number=True),
                   payload(number=0), payload(pull_request={}),
                   payload(pull_request={'number': 2, 'draft': False, 'state': 'open', 'head': {'sha': 'a'*40}}),
                   payload(pull_request={'number': 1, 'draft': 0, 'state': 'open', 'head': {'sha': 'a'*40}}),
                   payload(pull_request={'number': 1, 'draft': False, 'state': 'open', 'head': {'sha': 'bad'}})]
        for body in invalid:
            with self.subTest(body=body): self.assertEqual(self.send(body), 400)

    def test_full_queue_rejects_new_body_but_accepts_replay(self):
        with patch('receiver.MAX_QUEUE', 1, create=True):
            self.assertEqual(self.send(), 202)
            self.assertEqual(self.send(overrides={'X-GitHub-Delivery': 'other'}), 200)
            self.assertEqual(self.send(payload(action='reopened'), {'X-GitHub-Delivery': 'new'}), 503)

    def test_existing_database_permissions_are_restricted(self):
        from receiver import create_server
        import os
        os.chmod(self.db, 0o666)
        server = create_server('secret', {123: 'acme/repo'}, self.db, port=0)
        server.server_close()
        self.assertEqual(os.stat(self.db).st_mode & 0o777, 0o600)

    def test_requires_configuration(self):
        from receiver import create_server
        with self.assertRaises(ValueError): create_server('', {123: 'acme/repo'}, self.db, 0)
        with self.assertRaises(ValueError): create_server('secret', set(), self.db, 0)

if __name__ == '__main__': unittest.main()
