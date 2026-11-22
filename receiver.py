"""Local-only GitHub pull request webhook intake; no outbound operations.

At capacity, terminal skipped or failed work at least seven days old is replaced transactionally with permanent SHA-256
tombstones. Done results are retained indefinitely because publication uses a separate ledger.
This bounds queue rows, not tombstone or SQLite disk usage; backups
and disk monitoring are operator responsibilities. A restored or deleted database loses replay history since its backup.
The signature authenticates the body, not the delivery ID; tombstones cannot
prevent replay after database loss or protect against a compromised secret.
Pending, retrying, and leased work is never evicted; saturation returns 503.
"""
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
from outbox import Outbox, valid_identity

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
        db.execute('CREATE TABLE IF NOT EXISTS tombstone (delivery_id TEXT PRIMARY KEY, body_hash BLOB NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS webhook_signatures (delivery_id TEXT PRIMARY KEY, signature TEXT NOT NULL)')
        db.execute('CREATE INDEX IF NOT EXISTS tombstone_body_hash ON tombstone(body_hash)')

    Outbox(db_path, repos=allowed_repos)

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
                    or not valid_identity(repo_id, repo, number)
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
                    digest = hashlib.sha256(body).digest()
                    previous = db.execute('SELECT body_hash FROM tombstone WHERE delivery_id=?', (delivery,)).fetchone()
                    if previous is not None:
                        return self.reply(200 if previous[0] == digest else 409, 'duplicate' if previous[0] == digest else 'delivery conflict')
                    if db.execute('SELECT 1 FROM queue WHERE body = ? LIMIT 1', (body,)).fetchone():
                        return self.reply(200, 'duplicate')
                    if db.execute('SELECT 1 FROM tombstone WHERE body_hash=? LIMIT 1', (digest,)).fetchone():
                        return self.reply(200, 'duplicate')
                    if db.execute('SELECT COUNT(*) FROM queue').fetchone()[0] >= MAX_QUEUE:
                        # ponytail: evict one expired terminal result only when full;
                        # tombstones grow indefinitely to preserve replay defense.
                        if 'completed_at' in {r[1] for r in db.execute('PRAGMA table_info(work)')}:
                            row = db.execute("""SELECT q.delivery_id, q.body FROM queue q JOIN work w
                                ON w.delivery_id=q.delivery_id WHERE w.status IN ('skipped','failed')
                                AND w.completed_at <= CAST(strftime('%s','now') AS INTEGER) - 7 * 86400
                                AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.delivery_id=q.delivery_id
                                    AND o.status IS NOT 'sent')
                                ORDER BY w.completed_at, q.rowid LIMIT 1""").fetchone()
                            if row:
                                db.execute('INSERT INTO tombstone(delivery_id, body_hash) VALUES (?, ?)',
                                           (row[0], hashlib.sha256(row[1]).digest()))
                                db.execute('DELETE FROM work WHERE delivery_id=?', (row[0],))
                                db.execute('DELETE FROM webhook_signatures WHERE delivery_id=?', (row[0],))
                                db.execute('DELETE FROM queue WHERE delivery_id=?', (row[0],))
                        if db.execute('SELECT COUNT(*) FROM queue').fetchone()[0] >= MAX_QUEUE:
                            raise sqlite3.OperationalError('queue full')
                    db.execute('INSERT INTO queue (delivery_id, body) VALUES (?, ?)', (delivery, body))
                    db.execute('INSERT INTO webhook_signatures VALUES (?, ?)', (delivery, signature))
                    db.execute("UPDATE outbox SET repo_id=?,repo_name=?,pr_number=? WHERE delivery_id=? AND event='detected'", (repo_id, repo, number, delivery))
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
