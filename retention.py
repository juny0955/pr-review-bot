"""Explicit offline cleanup of one old, ledger-confirmed publication."""
from contextlib import closing
import hashlib
import hmac
import json
import re
from pathlib import Path
import sqlite3

from outbox import valid_identity
from worker import mode_provenance


def cleanup_done(queue_path, ledger_path, delivery_id, secret):
    """Stop all writers first; retain the ledger and backups for replay protection."""
    if not isinstance(secret, str) or not secret:
        raise ValueError('webhook secret required')
    # ponytail: one explicit delivery per call; bulk cleanup needs operator review.
    with closing(sqlite3.connect(Path(queue_path).resolve().as_uri() + '?mode=rw', uri=True)) as db, db:
        db.execute('ATTACH DATABASE ? AS ledger', (Path(ledger_path).resolve().as_uri() + '?mode=rw',))
        db.execute('BEGIN IMMEDIATE')
        columns = {row[1] for row in db.execute('PRAGMA table_info(work)')}
        mode = ','.join('w.' + name if name in columns else 'NULL' for name in ('publish_eligible', 'notifications_enabled', 'mode_provenance'))
        row = db.execute('''SELECT q.body,w.result,s.signature,''' + mode + ''' FROM queue q
            JOIN work w ON w.delivery_id=q.delivery_id
            JOIN webhook_signatures s ON s.delivery_id=q.delivery_id
            WHERE q.delivery_id=? AND w.status='done'
              AND w.completed_at <= CAST(strftime('%s','now') AS INTEGER)-7*86400''', (delivery_id,)).fetchone()
        if not row:
            return False
        body, result, signature, publish_eligible, notifications_enabled, provenance = row
        if ((publish_eligible, notifications_enabled) != (None, None)
                and (publish_eligible not in (0, 1) or notifications_enabled not in (0, 1))):
            return False
        if not isinstance(body, bytes) or not isinstance(signature, str) or not re.fullmatch(r'sha256=[0-9a-f]{64}', signature) or not hmac.compare_digest(
                signature, 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()):
            return False
        expected = mode_provenance(secret, delivery_id, body, publish_eligible, notifications_enabled)
        if not expected or not isinstance(provenance, str) or not re.fullmatch(r'[0-9a-f]{64}', provenance) or not hmac.compare_digest(provenance, expected):
            return False
        try:
            event, result = json.loads(body), json.loads(result)
            identity = (event['repository']['id'], event['repository']['full_name'], event['number'])
            head, base = event['pull_request']['head']['sha'], event['pull_request']['base']['sha']
            if (not valid_identity(*identity) or type(event['pull_request']['number']) is not int
                    or event['pull_request']['number'] != identity[2]
                    or not all(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha) for sha in (head, base))
                    or type(result['repo_id']) is not int or type(result['number']) is not int
                    or (result['repo_id'], result['repository'], result['number'], result['sha'], result['base_sha'])
                    != (*identity, head, base) or result['status'] != 'done' or not isinstance(result['review'], str)):
                return False
            rows = db.execute('SELECT event,status,repo_id,repo_name,pr_number FROM outbox WHERE delivery_id=?', (delivery_id,)).fetchall()
            if (not {'detected', 'started', 'completed'}.issubset({row[0] for row in rows})
                    or any(not (row[1] == 'sent' and row[2:] == identity
                                or notifications_enabled == 0 and row[1] == 'suppressed'
                                and all(old is None or (type(old) is type(new) and old == new)
                                        for old, new in zip(row[2:], identity))) for row in rows)):
                return False
            key_parts = ['v2', *identity, head, base, result['review']]
            key = hashlib.sha256(json.dumps(key_parts, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
            legacy_key = hashlib.sha256(json.dumps([*identity, head, result['review']], ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        except (KeyError, TypeError, ValueError, RecursionError):
            return False
        claims = db.execute('SELECT state FROM ledger.publications WHERE key=?', (key,)).fetchall()
        ledger_columns = {r[1] for r in db.execute('PRAGMA ledger.table_info(publications)')}
        marker = 'marker' if 'marker' in ledger_columns else 'NULL'
        legacy = db.execute(f'SELECT {marker},state FROM ledger.publications WHERE key=?', (legacy_key,)).fetchall()
        if legacy and legacy != [('pr-review-bot:v2-legacy-reservation', 'pending')]:
            return False
        if publish_eligible == 0:
            if notifications_enabled not in (0, 1) or claims or legacy:
                return False
        elif claims != [('sent',)]:
            return False
        db.execute('INSERT INTO tombstone(delivery_id,body_hash) VALUES (?,?)', (delivery_id, hashlib.sha256(body).digest()))
        db.execute('DELETE FROM work WHERE delivery_id=?', (delivery_id,))
        db.execute('DELETE FROM webhook_signatures WHERE delivery_id=?', (delivery_id,))
        db.execute('DELETE FROM queue WHERE delivery_id=?', (delivery_id,))
        return True
