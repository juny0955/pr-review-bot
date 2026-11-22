"""Offline dry-run queue processor. Adapters are injected; no live integrations."""
from contextlib import closing
import json
import itertools
import codecs
import stat
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

from repo_config import allowed
from outbox import Outbox

ACTIONS = frozenset({'opened', 'reopened', 'synchronize', 'ready_for_review'})
SHA = re.compile(r'[0-9a-f]{40}\Z')
MAX_DIFF = 1024 * 1024
MAX_REVIEW = 65536


def wiki_evidence(root, query=''):
    """Select bounded chunks of top-level Markdown without following symlinks."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        parts = os.fspath(root).split(os.sep)
        if '..' in parts:
            raise ValueError('wiki directory unavailable')
        anchor = '/' if os.path.isabs(root) else '.'
        root_fd = os.open(anchor, flags)
        directories: list[tuple[int | None, str, int]] = [(None, anchor, root_fd)]
        try:
            for part in parts:
                if part and part != '.':
                    next_fd = os.open(part, flags, dir_fd=root_fd)
                    directories.append((root_fd, part, next_fd))
                    root_fd = next_fd
        except BaseException:
            for _, _, fd in reversed(directories):
                os.close(fd)
            raise
    except OSError as exc:
        raise ValueError('wiki directory unavailable') from exc
    article_fd = root_fd
    prefix = ''
    try:
        try:
            os.stat('wiki', dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            try:
                article_fd = os.open('wiki', flags, dir_fd=root_fd)
            except OSError as exc:
                raise ValueError('wiki article directory unavailable') from exc
            directories.append((root_fd, 'wiki', article_fd))
            prefix = 'wiki/'
        def directories_current():
            try:
                for parent, name, fd in directories:
                    opened = os.fstat(fd)
                    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if not stat.S_ISDIR(current.st_mode) or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                        return False
                return True
            except OSError:
                return False
        if not directories_current():
            return []
        deadline = time.monotonic() + 2
        remaining = 4 * 1024 * 1024
        identities = {}
        def identity(s):
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        def validate(result):
            if not directories_current():
                return []
            try:
                if not prefix:
                    try:
                        os.stat('wiki', dir_fd=root_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        return []
                for path in {entry['path'] for entry in result}:
                    current = os.stat(path[len(prefix):], dir_fd=article_fd, follow_symlinks=False)
                    if identity(current) != identities[path]:
                        return []
            except OSError:
                return []
            return result
        terms = set(re.findall(r'[^\W_]{3,}', query[:1048576].casefold())) - {
            'diff', 'git', 'index', 'the', 'and', 'for', 'from', 'with'}
        def read(name):
            nonlocal remaining
            path = prefix + name
            try:
                if not name.lower().endswith('.md') or len(path.encode('utf-8')) > 255:
                    return []
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=article_fd)
                try:
                    before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode):
                        return []
                    limit = min(before.st_size, 256 * 1024, remaining)
                    content = bytearray()
                    while len(content) < limit and time.monotonic() < deadline:
                        data = os.read(fd, min(16384, limit - len(content)))
                        if not data:
                            break
                        content.extend(data)
                        remaining -= len(data)
                    after = os.fstat(fd)
                    current = os.stat(name, dir_fd=article_fd, follow_symlinks=False)
                    if identity(before) != identity(after) or identity(after) != identity(current) or len(content) != limit:
                        return []
                    decoder = codecs.getincrementaldecoder('utf-8')('strict')
                    data = decoder.decode(content, final=limit == before.st_size).encode('utf-8')
                    chunks = []
                    while data:
                        end = min(len(data), 16384)
                        while end < len(data) and data[end] & 0xc0 == 0x80:
                            end -= 1
                        chunks.append({'path': path, 'text': data[:end].decode('utf-8')})
                        data = data[end:]
                    identities[path] = identity(after)
                    return chunks or [{'path': path, 'text': ''}]
                finally:
                    os.close(fd)
            except (OSError, UnicodeError):
                return []
        index_chunks = read('index.md')
        index = index_chunks[:1]
        with os.scandir(article_fd) as entries:
            names = [entry.name for entry in itertools.islice(entries, 501)]
        # ponytail: reject overflow rather than select a filesystem-order subset.
        if len(names) > 500:
            return validate(index)
        names.sort()
        candidates = []
        for name in names:
            if time.monotonic() >= deadline or remaining <= 0:
                break
            entries = index_chunks[1:] if name == 'index.md' else read(name)
            for offset, entry in enumerate(entries):
                words = set(re.findall(r'[^\W_]{3,}', (name + ' ' + entry['text']).casefold()))
                candidates.append((len(terms & words), name, offset, entry))
        candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        # ponytail: checks cannot prevent changes after validation or ABA races.
        return validate(index + [item[3] for item in candidates[:20 - len(index)]])
    finally:
        for _, _, fd in reversed(directories):
            os.close(fd)


def mode_provenance(secret, delivery, body, publish, notifications):
    import hashlib
    import hmac
    if (not isinstance(secret, str) or not secret or not isinstance(delivery, str)
            or not isinstance(body, bytes) or publish not in (0, 1) or notifications not in (0, 1)):
        return None
    payload = json.dumps(['mode-v1', delivery, hashlib.sha256(body).hexdigest(), publish, notifications], separators=(',', ':')).encode()
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def valid_mode(secret, delivery, body, publish, notifications, provenance):
    import hmac
    expected = mode_provenance(secret, delivery, body, publish, notifications)
    return bool(expected and isinstance(provenance, str) and re.fullmatch(r'[0-9a-f]{64}', provenance)
                and hmac.compare_digest(provenance, expected))


def result_provenance(secret, delivery, body, publish, notifications, result):
    import hashlib
    import hmac
    if not mode_provenance(secret, delivery, body, publish, notifications) or not isinstance(result, str):
        return None
    payload = json.dumps(['result-v1', delivery, hashlib.sha256(body).hexdigest(), publish, notifications, result], ensure_ascii=True, separators=(',', ':')).encode()
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def valid_result(secret, delivery, body, publish, notifications, result, provenance):
    import hmac
    expected = result_provenance(secret, delivery, body, publish, notifications, result)
    return bool(expected and isinstance(provenance, str) and re.fullmatch(r'[0-9a-f]{64}', provenance)
                and hmac.compare_digest(provenance, expected))


class Worker:
    def __init__(self, db_path, github, model, wiki, repos, lease_seconds=300, clock=time.time,
                 *, publish_eligible=False, notifications_enabled=True, webhook_secret=None):
        if lease_seconds <= 0:
            raise ValueError('lease must be positive')
        if type(publish_eligible) is not bool or type(notifications_enabled) is not bool:
            raise ValueError('invalid job mode')
        self.publish_eligible, self.notifications_enabled = publish_eligible, notifications_enabled
        self.webhook_secret = webhook_secret
        allowed(repos)
        self.repos = repos
        self.db_path, self.github, self.model, self.wiki = db_path, github, model, wiki
        self.lease_seconds, self.clock = lease_seconds, clock
        Outbox(db_path, clock=clock, repos=repos)
        with closing(sqlite3.connect(db_path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''CREATE TABLE IF NOT EXISTS work (
                delivery_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                lease_token TEXT, lease_until REAL, attempts INTEGER NOT NULL DEFAULT 0,
                result TEXT, next_attempt_at REAL,
                FOREIGN KEY(delivery_id) REFERENCES queue(delivery_id))''')
            columns = {row[1] for row in db.execute('PRAGMA table_info(work)')}
            if 'next_attempt_at' not in columns:
                db.execute('ALTER TABLE work ADD COLUMN next_attempt_at REAL')
            if 'completed_at' not in columns:
                db.execute('ALTER TABLE work ADD COLUMN completed_at REAL')
                db.execute("UPDATE work SET completed_at=? WHERE status IN ('done','skipped','failed')", (self.clock(),))
            for column in ('publish_eligible', 'notifications_enabled'):
                if column not in columns:
                    db.execute(f'ALTER TABLE work ADD COLUMN {column} INTEGER')
            if 'mode_provenance' not in columns:
                db.execute('ALTER TABLE work ADD COLUMN mode_provenance TEXT')
            if 'result_provenance' not in columns:
                db.execute('ALTER TABLE work ADD COLUMN result_provenance TEXT')
            Outbox.install_work_triggers(db)

    def claim(self):
        if not isinstance(self.webhook_secret, str) or not self.webhook_secret:
            raise ValueError('webhook secret required')
        token = uuid.uuid4().hex
        with closing(sqlite3.connect(self.db_path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            now = self.clock()
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='webhook_signatures'").fetchone():
                return None
            import hashlib
            import hmac
            def valid_signature(body, signature):
                return bool(isinstance(body, bytes) and isinstance(signature, str)
                            and re.fullmatch(r'sha256=[0-9a-f]{64}', signature)
                            and hmac.compare_digest(signature, 'sha256=' + hmac.new(self.webhook_secret.encode(), body, hashlib.sha256).hexdigest()))
            db.create_function('valid_signature', 2, valid_signature)
            # A crashed final attempt must also become terminal; do not reclaim it.
            db.create_function('valid_mode', 5, lambda delivery, body, publish, notifications, mac:
                               valid_mode(self.webhook_secret, delivery, body, publish, notifications, mac))
            db.execute('''UPDATE work SET status='failed', lease_token=NULL, lease_until=NULL,
                next_attempt_at=NULL, result=?, completed_at=? WHERE attempts >= 3
                AND EXISTS (SELECT 1 FROM queue q WHERE q.delivery_id=work.delivery_id AND valid_mode(work.delivery_id,q.body,work.publish_eligible,work.notifications_enabled,work.mode_provenance)) AND
                (status='retry' OR (status='running' AND lease_until <= ?))''',
                (json.dumps({'status': 'failed', 'reason': 'processing failed'}), now, now))
            db.execute("UPDATE outbox SET status='suppressed' WHERE status='pending' AND delivery_id IN (SELECT w.delivery_id FROM work w JOIN queue q ON q.delivery_id=w.delivery_id WHERE w.notifications_enabled=0 AND valid_mode(w.delivery_id,q.body,w.publish_eligible,w.notifications_enabled,w.mode_provenance))")
            db.execute('''UPDATE work SET status='retry', next_attempt_at=lease_until +
                CASE attempts WHEN 1 THEN 30 ELSE 60 END, lease_token=NULL, lease_until=NULL,
                result=? WHERE status='running' AND lease_until <= ? AND attempts < 3
                AND EXISTS (SELECT 1 FROM queue q WHERE q.delivery_id=work.delivery_id AND valid_mode(work.delivery_id,q.body,work.publish_eligible,work.notifications_enabled,work.mode_provenance))''',
                (json.dumps({'status': 'retry', 'reason': 'processing failed'}), now))
            row = db.execute('''SELECT q.delivery_id, q.body FROM queue q
                LEFT JOIN work w ON w.delivery_id=q.delivery_id
                WHERE EXISTS (SELECT 1 FROM webhook_signatures s WHERE s.delivery_id=q.delivery_id AND valid_signature(q.body,s.signature))
                AND (w.delivery_id IS NULL OR (w.status='retry' AND COALESCE(w.next_attempt_at, 0) <= ?
                    AND w.publish_eligible=? AND w.notifications_enabled=? AND valid_mode(w.delivery_id,q.body,w.publish_eligible,w.notifications_enabled,w.mode_provenance)))
                ORDER BY q.rowid LIMIT 1''', (now, int(self.publish_eligible), int(self.notifications_enabled))).fetchone()
            if row is None:
                return None
            provenance = mode_provenance(self.webhook_secret, row[0], row[1], int(self.publish_eligible), int(self.notifications_enabled))
            if not provenance:
                raise ValueError('invalid mode provenance')
            db.execute('''INSERT INTO work(delivery_id,status,lease_token,lease_until,attempts,publish_eligible,notifications_enabled,mode_provenance)
                VALUES (?,'running',?,?,1,?,?,?)
                ON CONFLICT(delivery_id) DO UPDATE SET status='running',
                lease_token=excluded.lease_token, lease_until=excluded.lease_until,
                attempts=work.attempts+1, result=NULL''', (row[0], token, now + self.lease_seconds,
                    int(self.publish_eligible), int(self.notifications_enabled), provenance))
            if not self.notifications_enabled:
                db.execute("UPDATE outbox SET status='suppressed' WHERE delivery_id=? AND status='pending'", (row[0],))
        return row[0], row[1], token

    def finish(self, delivery, token, status, result):
        with closing(sqlite3.connect(self.db_path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            now = self.clock()
            row = db.execute('''SELECT w.attempts,q.body,w.publish_eligible,w.notifications_enabled,w.mode_provenance FROM work w JOIN queue q ON q.delivery_id=w.delivery_id WHERE w.delivery_id=? AND w.status='running'
                AND lease_token=? AND lease_until > ?''', (delivery, token, now)).fetchone()
            if row is None:
                return False
            if not valid_mode(self.webhook_secret, delivery, row[1], row[2], row[3], row[4]):
                return False
            next_attempt = None
            if status == 'retry':
                if row[0] >= 3:
                    status = 'failed'
                    result['status'] = 'failed'
                else:
                    next_attempt = now + 30 * (2 ** (row[0] - 1))
            serialized = json.dumps(result, ensure_ascii=True)
            mac = result_provenance(self.webhook_secret, delivery, row[1], row[2], row[3], serialized) if status == 'done' else None
            db.execute('''UPDATE work SET status=?,result=?,result_provenance=?,lease_token=NULL,lease_until=NULL,
                next_attempt_at=?, completed_at=? WHERE delivery_id=?''',
                (status, serialized, mac, next_attempt,
                 now if status in ('done', 'skipped', 'failed') else None, delivery))
            if not self.notifications_enabled:
                db.execute("UPDATE outbox SET status='suppressed' WHERE delivery_id=? AND status='pending'", (delivery,))
            return True

    def run_once(self):
        claim = self.claim()
        if claim is None:
            return None
        delivery, body, token = claim
        try:
            result = self.process(body)
            status = result['status']
        except Exception:
            # Do not persist exception text; adapters may include credentials or PR content.
            result = {'status': 'retry', 'reason': 'processing failed'}
            status = 'retry'
        if not self.finish(delivery, token, status, result):
            return {'status': 'lease_lost'}
        return result

    def process(self, body):
        policy = allowed(self.repos)
        try:
            event = json.loads(body)
            repo = event['repository']['full_name']
            repo_id = event['repository']['id']
            pr = event['pull_request']
            number = event['number']
            sha = pr['head']['sha']
            if (type(repo_id) is not int or policy.get(repo_id) != repo or event['action'] not in ACTIONS or
                type(number) is not int or number <= 0 or pr['number'] != number or
                pr['draft'] is not False or pr['state'] != 'open' or
                not isinstance(sha, str) or not SHA.fullmatch(sha)):
                return {'status': 'skipped', 'reason': 'ineligible event'}
        except (ValueError, KeyError, TypeError):
            return {'status': 'skipped', 'reason': 'invalid event'}
        def eligible(base_sha=None):
            if allowed(self.repos).get(repo_id) != repo:
                return None
            state = self.github.current(repo, number)
            current_base = state.get('base_sha')
            if (state.get('state') != 'open' or state.get('draft') is not False
                    or state.get('sha') != sha):
                return None
            if not isinstance(current_base, str) or not SHA.fullmatch(current_base):
                raise ValueError('invalid base SHA')
            if base_sha is not None and current_base != base_sha:
                raise ValueError('base changed during review')
            return current_base
        base_sha = eligible()
        if base_sha is None:
            return {'status': 'skipped', 'reason': 'stale or ineligible PR'}
        diff = self.github.diff(repo, number, sha, base_sha)
        if not isinstance(diff, str) or len(diff.encode('utf-8')) > MAX_DIFF:
            return {'status': 'skipped', 'reason': 'invalid or oversized diff'}
        request = {'repository': repo, 'number': number, 'sha': sha, 'diff': diff,
                   'wiki': wiki_evidence(self.wiki, diff), 'profile': 'prreview', 'model': 'gpt-6.1-terra'}
        review = self.model.review(request)
        if not isinstance(review, str) or not review.strip() or len(review.encode('utf-8')) > MAX_REVIEW:
            raise ValueError('invalid review')
        if eligible(base_sha) is None:
            return {'status': 'skipped', 'reason': 'stale or ineligible PR'}
        return {'status': 'done', 'repo_id': repo_id, 'repository': repo, 'number': number, 'sha': sha,
                'base_sha': base_sha, 'review': review}
