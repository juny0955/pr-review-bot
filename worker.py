"""Offline dry-run queue processor. Adapters are injected; no live integrations."""
from contextlib import closing
import json
import itertools
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
    """Read the vault's wiki/ articles (or an article directory), never symlinks.

    Scan at most 500 directory entries, prioritizing the index and keyword
    matches. Paths are relative to the configured root for provenance.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_fd = os.open(root, flags)
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
            prefix = 'wiki/'
        terms = set(re.findall(r'[^\W_]{3,}', query.casefold())) - {
            'diff', 'git', 'index', 'the', 'and', 'for', 'from', 'with'}
        def read(name):
            path = prefix + name
            if not name.lower().endswith('.md') or len(path.encode('utf-8')) > 255:
                return None
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=article_fd)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        return None
                    with os.fdopen(fd, 'rb', closefd=False) as f:
                        content = f.read(16_385)
                    if len(content) > 16_384:
                        return None
                    return {'path': path, 'text': content.decode('utf-8')}
                finally:
                    os.close(fd)
            except (OSError, UnicodeError):
                return None
        index = read('index.md')
        with os.scandir(article_fd) as entries:
            names = sorted(entry.name for entry in itertools.islice(entries, 500))
        candidates = []
        for name in names:
            if name == 'index.md':
                continue
            entry = read(name)
            if entry is not None:
                words = set(re.findall(r'[^\W_]{3,}', (name + ' ' + entry['text']).casefold()))
                candidates.append((len(terms & words), name, entry))
        candidates.sort(key=lambda item: (-item[0], item[1]))
        return ([index] if index else []) + [item[2] for item in candidates[:20 - bool(index)]]
    finally:
        if article_fd != root_fd:
            os.close(article_fd)
        os.close(root_fd)


class Worker:
    def __init__(self, db_path, github, model, wiki, repos, lease_seconds=300, clock=time.time):
        if lease_seconds <= 0:
            raise ValueError('lease must be positive')
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
            Outbox.install_work_triggers(db)

    def claim(self):
        token = uuid.uuid4().hex
        with closing(sqlite3.connect(self.db_path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            now = self.clock()
            # A crashed final attempt must also become terminal; do not reclaim it.
            db.execute('''UPDATE work SET status='failed', lease_token=NULL, lease_until=NULL,
                next_attempt_at=NULL, result=?, completed_at=? WHERE attempts >= 3 AND
                (status='retry' OR (status='running' AND lease_until <= ?))''',
                (json.dumps({'status': 'failed', 'reason': 'processing failed'}), now, now))
            db.execute('''UPDATE work SET status='retry', next_attempt_at=lease_until +
                CASE attempts WHEN 1 THEN 30 ELSE 60 END, lease_token=NULL, lease_until=NULL,
                result=? WHERE status='running' AND lease_until <= ? AND attempts < 3''',
                (json.dumps({'status': 'retry', 'reason': 'processing failed'}), now))
            row = db.execute('''SELECT q.delivery_id, q.body FROM queue q
                LEFT JOIN work w ON w.delivery_id=q.delivery_id
                WHERE w.delivery_id IS NULL OR (w.status='retry' AND COALESCE(w.next_attempt_at, 0) <= ?)
                ORDER BY q.rowid LIMIT 1''', (now,)).fetchone()
            if row is None:
                return None
            db.execute('''INSERT INTO work(delivery_id,status,lease_token,lease_until,attempts)
                VALUES (?,'running',?,?,1)
                ON CONFLICT(delivery_id) DO UPDATE SET status='running',
                lease_token=excluded.lease_token, lease_until=excluded.lease_until,
                attempts=work.attempts+1, result=NULL''', (row[0], token, now + self.lease_seconds))
        return row[0], row[1], token

    def finish(self, delivery, token, status, result):
        with closing(sqlite3.connect(self.db_path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            now = self.clock()
            row = db.execute('''SELECT attempts FROM work WHERE delivery_id=? AND status='running'
                AND lease_token=? AND lease_until > ?''', (delivery, token, now)).fetchone()
            if row is None:
                return False
            next_attempt = None
            if status == 'retry':
                if row[0] >= 3:
                    status = 'failed'
                    result['status'] = 'failed'
                else:
                    next_attempt = now + 30 * (2 ** (row[0] - 1))
            db.execute('''UPDATE work SET status=?,result=?,lease_token=NULL,lease_until=NULL,
                next_attempt_at=?, completed_at=? WHERE delivery_id=?''',
                (status, json.dumps(result, ensure_ascii=True), next_attempt,
                 now if status in ('done', 'skipped', 'failed') else None, delivery))
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
