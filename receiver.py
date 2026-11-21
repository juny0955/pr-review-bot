"""Local-only GitHub pull request webhook intake; no outbound operations."""
from contextlib import closing
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from repo_config import allowed

MAX_BODY = 1024 * 1024
MAX_QUEUE = 1000


def create_server(secret, allowed_repos, db_path, port=8080):
    if not secret or not allowed_repos:
        raise ValueError('secret and repository allowlist are required')
    key = secret.encode('utf-8')
    allowed(allowed_repos)
    fd = os.open(db_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('database must be a regular file')
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute('CREATE TABLE IF NOT EXISTS queue (delivery_id TEXT PRIMARY KEY, body BLOB NOT NULL, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *args):
            pass

        def reply(self, status, message):
            data = (message + '\n').encode()
            self.send_response(status)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

        def do_POST(self):
            if self.path != '/webhook':
                return self.reply(404, 'not found')
            names = ('Content-Length', 'X-Hub-Signature-256', 'X-GitHub-Event', 'X-GitHub-Delivery')
            if self.headers.get('Transfer-Encoding') or any(len(self.headers.get_all(n, [])) != 1 for n in names):
                return self.reply(400, 'invalid headers')
            length = self.headers['Content-Length']
            if not re.fullmatch(r'[0-9]{1,8}', length):
                return self.reply(400, 'invalid length')
            length = int(length)
            if length > MAX_BODY:
                return self.reply(413, 'payload too large')
            body = self.rfile.read(length)
            if len(body) != length:
                return self.reply(400, 'incomplete body')
            signature = self.headers['X-Hub-Signature-256']
            expected = 'sha256=' + hmac.new(key, body, hashlib.sha256).hexdigest()
            if not re.fullmatch(r'sha256=[0-9a-f]{64}', signature) or not hmac.compare_digest(signature, expected):
                return self.reply(401, 'invalid signature')
            delivery = self.headers['X-GitHub-Delivery']
            if not re.fullmatch(r'[A-Za-z0-9-]{1,128}', delivery):
                return self.reply(400, 'invalid delivery')
            if self.headers['X-GitHub-Event'] != 'pull_request':
                return self.reply(400, 'unsupported event')
            try:
                payload = json.loads(body)
                repo = payload['repository']['full_name']
                repo_id = payload['repository'].get('id')
                try:
                    policy = allowed(allowed_repos)
                except (OSError, ValueError, TypeError):
                    return self.reply(503, 'repository configuration unavailable')
                if type(repo_id) is not int or policy.get(repo_id) != repo:
                    return self.reply(403, 'repository not allowed')
                action = payload['action']
                number = payload['number']
                pr = payload['pull_request']
                sha = pr['head']['sha']
                if (not isinstance(action, str) or action not in ('opened', 'reopened', 'synchronize', 'ready_for_review')
                    or type(number) is not int or number <= 0
                    or type(pr['number']) is not int or pr['number'] != number
                    or type(pr['draft']) is not bool or pr['state'] not in ('open', 'closed')
                    or not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40}', sha)):
                    return self.reply(400, 'invalid payload')
            except (ValueError, KeyError, TypeError, RecursionError):
                return self.reply(400, 'invalid payload')
            try:
                with closing(sqlite3.connect(db_path, timeout=5)) as db, db:
                    db.execute('BEGIN IMMEDIATE')
                    previous = db.execute('SELECT body FROM queue WHERE delivery_id = ?', (delivery,)).fetchone()
                    if previous is not None:
                        return self.reply(200 if previous[0] == body else 409, 'duplicate' if previous[0] == body else 'delivery conflict')
                    if db.execute('SELECT 1 FROM queue WHERE body = ? LIMIT 1', (body,)).fetchone():
                        return self.reply(200, 'duplicate')
                    if db.execute('SELECT COUNT(*) FROM queue').fetchone()[0] >= MAX_QUEUE:
                        return self.reply(503, 'queue full')
                    try:
                        db.execute('INSERT INTO queue (delivery_id, body) VALUES (?, ?)', (delivery, body))
                    except sqlite3.IntegrityError:
                        previous = db.execute('SELECT body FROM queue WHERE delivery_id = ?', (delivery,)).fetchone()
                        return self.reply(200 if previous and previous[0] == body else 409, 'duplicate' if previous and previous[0] == body else 'delivery conflict')
                return self.reply(202, 'queued')
            except sqlite3.Error:
                return self.reply(503, 'queue unavailable')

    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def main():
    secret = os.environ.get('WEBHOOK_SECRET', '')
    repos = os.environ.get('REPO_CONFIG', 'repos.json')
    db = os.environ.get('QUEUE_DB', 'queue.sqlite3')
    port = int(os.environ.get('PORT', '8080'))
    server = create_server(secret, repos, db, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
