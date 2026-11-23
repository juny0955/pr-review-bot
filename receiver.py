"""Local-only GitHub pull request webhook intake; no outbound operations.

Queue entries are never automatically evicted; saturation returns 503.
Offline retention may replace eligible results with permanent SHA-256 tombstones.
Backups and disk monitoring are operator responsibilities. A restored or deleted database loses replay history since its backup.
The signature authenticates the body, not the delivery ID; tombstones cannot
prevent replay after database loss or protect against a compromised secret.
"""
from contextlib import closing
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from repo_config import allowed
from outbox import Outbox, valid_identity

MAX_BODY = 1024 * 1024
MAX_QUEUE = 1000


def create_server(secret, allowed_repos, db_path, port=8080, *, installation_id=None):
    if not secret or not allowed_repos:
        raise ValueError('secret and repository allowlist are required')
    if installation_id is not None and (type(installation_id) is not int or not 0 < installation_id < 2**63):
        raise ValueError('invalid installation ID')
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
        db.execute('CREATE TABLE IF NOT EXISTS webhook_semantic (event_key BLOB PRIMARY KEY)')
        db.execute('CREATE TABLE IF NOT EXISTS webhook_alias (delivery_id TEXT PRIMARY KEY, body_hash BLOB NOT NULL)')

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
                if not isinstance(payload, dict):
                    return self.reply(400, 'invalid payload')
                # ponytail: missing installation is indistinguishable from a legacy hook with the same secret.
                if installation_id is not None and 'installation' in payload:
                    installation = payload['installation']
                    if (not isinstance(installation, dict) or type(installation.get('id')) is not int
                            or installation['id'] != installation_id):
                        return self.reply(403, 'installation not allowed')
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
                # ponytail: incomplete legacy payloads use exact-body deduplication.
                event_key = None
                base = pr.get('base', {}).get('sha') if isinstance(pr.get('base'), dict) else None
                updated = pr.get('updated_at')
                if isinstance(base, str) and re.fullmatch(r'[0-9a-f]{40}', base) and isinstance(updated, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', updated):
                    datetime.strptime(updated, '%Y-%m-%dT%H:%M:%SZ')
                    event_key = hashlib.sha256(json.dumps([repo_id, number, action, sha, base, pr['state'], pr['draft'], updated], separators=(',', ':')).encode()).digest()
            except (ValueError, KeyError, TypeError, RecursionError):
                return self.reply(400, 'invalid payload')
            try:
                with closing(sqlite3.connect(db_path, timeout=5)) as db, db:
                    db.execute('BEGIN IMMEDIATE')
                    previous = db.execute('SELECT body FROM queue WHERE delivery_id = ?', (delivery,)).fetchone()
                    if previous is not None:
                        return self.reply(200 if previous[0] == body else 409, 'duplicate' if previous[0] == body else 'delivery conflict')
                    digest = hashlib.sha256(body).digest()
                    previous = db.execute('SELECT body_hash FROM webhook_alias WHERE delivery_id=?', (delivery,)).fetchone()
                    if previous is not None:
                        return self.reply(200 if previous[0] == digest else 409, 'duplicate' if previous[0] == digest else 'delivery conflict')
                    previous = db.execute('SELECT body_hash FROM tombstone WHERE delivery_id=?', (delivery,)).fetchone()
                    if previous is not None:
                        return self.reply(200 if previous[0] == digest else 409, 'duplicate' if previous[0] == digest else 'delivery conflict')
                    if (db.execute('SELECT 1 FROM queue WHERE body = ? LIMIT 1', (body,)).fetchone()
                            or db.execute('SELECT 1 FROM tombstone WHERE body_hash=? LIMIT 1', (digest,)).fetchone()
                            or (event_key is not None and db.execute('SELECT 1 FROM webhook_semantic WHERE event_key=?', (event_key,)).fetchone())):
                        db.execute('INSERT INTO webhook_alias VALUES (?, ?)', (delivery, digest))
                        db.commit()
                        return self.reply(200, 'duplicate')
                    if db.execute('SELECT COUNT(*) FROM queue').fetchone()[0] >= MAX_QUEUE:
                        # ponytail: retain every row; only offline retention may delete.
                        raise sqlite3.OperationalError('queue full')
                    db.execute('INSERT INTO queue (delivery_id, body) VALUES (?, ?)', (delivery, body))
                    db.execute('INSERT INTO webhook_signatures VALUES (?, ?)', (delivery, signature))
                    if event_key is not None:
                        db.execute('INSERT INTO webhook_semantic VALUES (?)', (event_key,))
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
    installation = os.environ.get('GITHUB_APP_INSTALLATION_ID')
    if installation is not None:
        if not re.fullmatch(r'[0-9]{1,19}', installation):
            raise ValueError('invalid installation ID')
        installation = int(installation)
    server = create_server(secret, repos, db, port, installation_id=installation)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
