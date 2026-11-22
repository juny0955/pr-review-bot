"""Opt-in publisher with a durable, fail-closed publication ledger.

The injected current callable must independently fetch repository identity. The
post callable must raise on any unsuccessful or uncertain HTTP outcome. The get
callable returns a decoded GitHub review-list page or raises. A missing marker
never proves a POST failed; ambiguous claims are never automatically retried.
This cannot provide exactly-once delivery across GitHub and local storage.
"""
from contextlib import closing
import hashlib
import os
import json
import sqlite3
import uuid
import re

from repo_config import allowed

SHA = re.compile(r'[0-9a-f]{40}\Z')
# ponytail: known patterns only; use a maintained secret scanner for broader coverage.
SECRET = re.compile(
    r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|'
    r'\b(?:gh[opusr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|'
    r'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b|'
    r'\bBearer\s+[A-Za-z0-9._~+/=-]{8,}|'
    r'''\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd)\b["']?\s*[:=]\s*["']?[^\s"',;]{4,}''',
    re.IGNORECASE,
)


def _require_operational_isolation():
    # ponytail: no override until publisher/admin isolation and bypass prevention are verified.
    raise ValueError('publication disabled: operational isolation not implemented')


def _require_revocation_gate(path, identity):
    from revocation_gate import authorize
    return authorize(path, identity)


def _guard_publish(publish_locked):
    def guarded(self, repo_id, repo, number, sha, review, base_sha):
        if (type(repo_id) is not int or not isinstance(repo, str) or allowed(self.repos).get(repo_id) != repo
                or type(number) is not int or number <= 0):
            raise ValueError('repository or pull request not allowed')
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise ValueError('invalid SHA')
        if not isinstance(base_sha, str) or not SHA.fullmatch(base_sha):
            raise ValueError('invalid base SHA')
        if not isinstance(review, str) or not review.strip() or len(review.encode('utf-8')) > 65536:
            raise ValueError('invalid review')
        if SECRET.search(review):
            raise ValueError('review contains a potential secret')
        if not self.enabled:
            return 'dry_run'
        if not self.single_vps_mvp:
            _require_operational_isolation()
        elif repo != 'juny0955/pr-review-bot':
            raise ValueError('MVP repository not allowed')
        identity = [repo_id, repo, number, sha, base_sha, hashlib.sha256(review.encode('utf-8')).hexdigest()]
        # ponytail: one global lock serializes all posts; shard only if throughput requires it.
        with _require_revocation_gate(self.gate_path, identity):
            return publish_locked(self, repo_id, repo, number, sha, review, base_sha)
    return guarded


class GitHubPublisher:
    def __init__(self, post, current, repos, *, enabled=False, ledger_path=None, get=None, gate_path=None, single_vps_mvp=False):
        if type(enabled) is not bool or type(single_vps_mvp) is not bool:
            raise ValueError('enabled must be boolean')
        allowed(repos)
        self.post = post
        self.current = current
        self.repos = repos
        self.enabled = enabled
        self.ledger_path = ledger_path
        self.get = get
        self.gate_path = gate_path
        self.single_vps_mvp = single_vps_mvp

    def publish(self, repo_id, repo, number, sha, review, *, base_sha=None):
        return self._publish_locked(repo_id, repo, number, sha, review, base_sha)

    @_guard_publish
    def _publish_locked(self, repo_id, repo, number, sha, review, base_sha):
        actual = self.current(repo, number)
        if (not isinstance(actual, dict) or type(actual.get('repo_id')) is not int
                or actual.get('repo_id') != repo_id or actual.get('repo') != repo
                or actual.get('state') != 'open' or actual.get('draft') is not False
                or actual.get('sha') != sha or actual.get('base_sha') != base_sha or allowed(self.repos).get(repo_id) != repo):
            raise ValueError('stale, ineligible or mismatched pull request')
        if (not isinstance(self.ledger_path, (str, os.PathLike)) or not str(self.ledger_path)
                or str(self.ledger_path) == ':memory:' or str(self.ledger_path).startswith('file:')
                or not callable(self.get)):
            raise ValueError('durable ledger and review-list transport required')
        legacy_key = hashlib.sha256(json.dumps([repo_id, repo, number, sha, review],
                                             ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        key = hashlib.sha256(json.dumps(['v2', repo_id, repo, number, sha, base_sha, review],
                                      ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        endpoint = f'repos/{repo}/pulls/{number}/reviews'
        # A committed claim precedes any network write and survives a process crash.
        with closing(sqlite3.connect(self.ledger_path, timeout=30)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS publications (key TEXT PRIMARY KEY, marker TEXT NOT NULL, state TEXT NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            # Reserve the legacy key in the same transaction as the v2 claim.
            # Old publishers then see a pending claim and cannot POST. A real
            # legacy claim has no base identity and must remain ambiguous.
            sentinel = 'pr-review-bot:v2-legacy-reservation'
            legacy = db.execute('SELECT marker, state FROM publications WHERE key = ?', (legacy_key,)).fetchone()
            if legacy is None:
                db.execute('INSERT INTO publications VALUES (?, ?, ?)', (legacy_key, sentinel, 'pending'))
            elif legacy != (sentinel, 'pending'):
                return 'ambiguous'
            marker = '<!-- pr-review-bot:' + uuid.uuid4().hex + ' -->'
            claimed = db.execute('INSERT OR IGNORE INTO publications VALUES (?, ?, ?)',
                                 (key, marker, 'pending')).rowcount == 1
            if not claimed:
                marker, state = db.execute('SELECT marker, state FROM publications WHERE key = ?', (key,)).fetchone()
        if not claimed:
            if state == 'sent':
                return 'sent'
            if state not in ('pending', 'ambiguous'):
                raise ValueError('invalid ledger state')
            # A complete positive match is evidence of delivery; absence is not
            # evidence of non-delivery, even if every page was read successfully.
            try:
                # ponytail: scan at most 10,000 reviews; larger histories need operator reconciliation.
                for page in range(1, 1001):
                    reviews = self.get(f'{endpoint}?per_page=10&page={page}')
                    if not isinstance(reviews, list):
                        return 'ambiguous'
                    for item in reviews:
                        if (isinstance(item, dict) and item.get('commit_id') == sha
                                and isinstance(item.get('body'), str)
                                and marker in item['body']):
                            with closing(sqlite3.connect(self.ledger_path, timeout=30)) as db, db:
                                db.execute("UPDATE publications SET state = 'sent' WHERE key = ?", (key,))
                            return 'sent'
                    if len(reviews) < 10:
                        break
            except Exception:
                pass
            return 'ambiguous'
        try:
            self.post(endpoint, {'commit_id': sha, 'event': 'COMMENT',
                                 'body': review + '\n\n' + marker})
        except Exception:
            with closing(sqlite3.connect(self.ledger_path, timeout=30)) as db, db:
                db.execute("UPDATE publications SET state = 'ambiguous' WHERE key = ? AND state = 'pending'", (key,))
            return 'ambiguous'
        with closing(sqlite3.connect(self.ledger_path, timeout=30)) as db, db:
            db.execute("UPDATE publications SET state = 'sent' WHERE key = ?", (key,))
        return 'sent'
