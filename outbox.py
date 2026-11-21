"""Durable, at-least-once notification outbox; Discord can receive duplicates."""
from contextlib import closing
import json
import sqlite3
import time
import uuid
from repo_config import NAME, allowed


def valid_identity(repo_id, name, number):
    return (type(repo_id) is int and 0 < repo_id <= 9223372036854775807
            and isinstance(name, str) and len(name) <= 200 and NAME.fullmatch(name)
            and all(part not in ('.', '..') for part in name.split('/'))
            and type(number) is int and 0 < number <= 9223372036854775807)


class Outbox:
    def __init__(self, db_path, *, clock=time.time, lease_seconds=60, repos=None):
        if lease_seconds <= 0:
            raise ValueError('invalid lease')
        self.db_path, self.clock, self.lease_seconds, self.repos = db_path, clock, lease_seconds, repos
        with closing(sqlite3.connect(db_path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY, delivery_id TEXT NOT NULL, event TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
                lease_token TEXT, lease_until REAL,
                UNIQUE(delivery_id, event, attempt))''')
            columns = {row[1] for row in db.execute('PRAGMA table_info(outbox)')}
            for column, kind in [('repo_id', 'INTEGER'), ('repo_name', 'TEXT'), ('pr_number', 'INTEGER')]:
                if column not in columns:
                    db.execute(f'ALTER TABLE outbox ADD COLUMN {column} {kind}')
            db.execute('''CREATE TRIGGER IF NOT EXISTS outbox_detected AFTER INSERT ON queue BEGIN
                INSERT OR IGNORE INTO outbox(delivery_id,event) VALUES (NEW.delivery_id,'detected');
                END''')
            db.execute("INSERT OR IGNORE INTO outbox(delivery_id,event) SELECT delivery_id,'detected' FROM queue")
            # Legacy identity failures must remain recoverable, including partial migrations.
            db.execute("UPDATE outbox SET status='pending',next_attempt=0,attempts=0 WHERE status='failed' AND (repo_id IS NULL OR repo_name IS NULL OR pr_number IS NULL)")
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='work'").fetchone():
                self.install_work_triggers(db)

    @staticmethod
    def install_work_triggers(db):
        for name in ('outbox_started_insert', 'outbox_started_update', 'outbox_finished'):
            db.execute(f'DROP TRIGGER IF EXISTS {name}')
        db.execute('''CREATE TRIGGER outbox_started_insert AFTER INSERT ON work
            WHEN NEW.status='running' BEGIN
            INSERT OR IGNORE INTO outbox(delivery_id,event,attempt,repo_id,repo_name,pr_number)
            SELECT NEW.delivery_id,'started',NEW.attempts,repo_id,repo_name,pr_number FROM outbox
            WHERE delivery_id=NEW.delivery_id AND event='detected' AND attempt=0; END''')
        db.execute('''CREATE TRIGGER outbox_started_update AFTER UPDATE OF status ON work
            WHEN NEW.status='running' AND OLD.status!='running' BEGIN
            INSERT OR IGNORE INTO outbox(delivery_id,event,attempt,repo_id,repo_name,pr_number)
            SELECT NEW.delivery_id,'started',NEW.attempts,repo_id,repo_name,pr_number FROM outbox
            WHERE delivery_id=NEW.delivery_id AND event='detected' AND attempt=0; END''')
        db.execute('''CREATE TRIGGER outbox_finished AFTER UPDATE OF status ON work
            WHEN NEW.status IN ('done','failed') AND OLD.status!=NEW.status BEGIN
            INSERT OR IGNORE INTO outbox(delivery_id,event,repo_id,repo_name,pr_number)
            SELECT NEW.delivery_id,CASE NEW.status WHEN 'done' THEN 'completed' ELSE 'failed' END,
            repo_id,repo_name,pr_number FROM outbox
            WHERE delivery_id=NEW.delivery_id AND event='detected' AND attempt=0; END''')

    def claim(self):
        now, token = self.clock(), uuid.uuid4().hex
        with closing(sqlite3.connect(self.db_path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("UPDATE outbox SET status='failed',lease_token=NULL,lease_until=NULL WHERE status='sending' AND lease_until<=? AND attempts>=3", (now,))
            db.execute("UPDATE outbox SET status='pending',next_attempt=lease_until + CASE attempts WHEN 1 THEN 30 ELSE 60 END,lease_token=NULL,lease_until=NULL WHERE status='sending' AND lease_until<=? AND attempts<3", (now,))
            row = db.execute("SELECT id,event,repo_id,repo_name,pr_number FROM outbox WHERE status='pending' AND next_attempt<=? ORDER BY id LIMIT 1", (now,)).fetchone()
            if row is None:
                return None
            db.execute("UPDATE outbox SET status='sending', attempts=attempts+1,lease_token=?,lease_until=? WHERE id=?", (token, now+self.lease_seconds, row[0]))
            return row[0], row[1], token, *row[2:]

    def send_once(self, send):
        claim = self.claim()
        if claim is None:
            return None
        ident, event, token, repo_id, name, number = claim
        messages = {'detected': 'PR detected.', 'started': 'PR review started.',
                    'completed': 'PR review completed (dry run).', 'failed': 'PR review failed.'}
        try:
            policy = allowed(self.repos)
        except Exception:
            policy = {}
        identity = (repo_id, name, number)
        if any(value is None for value in identity):
            with closing(sqlite3.connect(self.db_path, timeout=5)) as db, db:
                db.execute('BEGIN IMMEDIATE')
                row = db.execute("SELECT q.body FROM outbox o LEFT JOIN queue q ON q.delivery_id=o.delivery_id WHERE o.id=? AND o.status='sending' AND o.lease_token=? AND o.lease_until>?", (ident, token, self.clock())).fetchone()
                try:
                    data = json.loads(row[0])
                    candidate = (data['repository']['id'], data['repository']['full_name'], data['number'])
                    if (valid_identity(*candidate) and policy.get(candidate[0]) == candidate[1]
                            and type(data['pull_request']['number']) is int and data['pull_request']['number'] == candidate[2]
                            and all(old is None or (type(old) is type(new) and old == new) for old, new in zip(identity, candidate))):
                        db.execute('UPDATE outbox SET repo_id=?,repo_name=?,pr_number=? WHERE id=?', (*candidate, ident))
                        identity = candidate
                except (ValueError, KeyError, TypeError, RecursionError, IndexError):
                    pass
        repo_id, name, number = identity
        incomplete = any(value is None for value in identity)
        invalid = not valid_identity(*identity) or event not in messages
        held = incomplete or (not invalid and policy.get(repo_id) != name)
        try:
            if not invalid and not held:
                send(f'{messages[event]} `{name} #{number}` (repository ID {repo_id})')
            ok = not invalid and not held
        except Exception:
            # Never store exception text: transport errors can contain credentials.
            ok = False
        now = self.clock()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT attempts FROM outbox WHERE id=? AND status='sending' AND lease_token=? AND lease_until>?", (ident, token, now)).fetchone()
            if row is None:
                return 'lease_lost'
            status = 'held' if held else ('sent' if ok else ('failed' if invalid or row[0] >= 3 else 'retry'))
            db.execute("UPDATE outbox SET status=?, next_attempt=?,attempts=attempts-?,lease_token=NULL,lease_until=NULL WHERE id=?", ('pending' if status in ('retry', 'held') else status, now + (30 if status == 'held' else 30 * (2 ** (row[0]-1))) if status in ('retry', 'held') else 0, int(held), ident))
            return status
