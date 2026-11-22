"""Publish a stored worker result by delivery ID, independently of notifications.

The approval callback is only an additional veto, never evidence for the gate.
Single-VPS publication is an explicit opt-in and does not provide account isolation.
Done results are retained indefinitely; skipped and failed results may expire at capacity.
"""
from contextlib import closing
import json
import hashlib
import hmac
import sqlite3

from publisher import GitHubPublisher
from worker import ACTIONS, mode_provenance, valid_result


def publish_worker_result(db_path, delivery_id, *, post, current, repos, get=None,
                          ledger_path=None, enabled=False, approve=None, gate_path=None,
                          single_vps_mvp=False, webhook_secret=None):
    if type(enabled) is not bool:
        raise ValueError('enabled must be boolean')
    with closing(sqlite3.connect(db_path, timeout=5)) as db:
        row = db.execute('''SELECT q.body, w.result FROM queue q JOIN work w
            ON w.delivery_id=q.delivery_id WHERE q.delivery_id=? AND w.status='done' ''',
                         (delivery_id,)).fetchone()
        if enabled:
            try:
                signature = db.execute('SELECT signature FROM webhook_signatures WHERE delivery_id=?', (delivery_id,)).fetchone()
                mode = db.execute('SELECT publish_eligible,notifications_enabled,mode_provenance,result_provenance FROM work WHERE delivery_id=?', (delivery_id,)).fetchone()
            except sqlite3.Error:
                raise ValueError('signed webhook unavailable') from None
            if (not row or not signature or not isinstance(webhook_secret, str) or not webhook_secret
                    or not isinstance(row[0], bytes) or not isinstance(signature[0], str)
                    or not hmac.compare_digest(signature[0], 'sha256=' + hmac.new(webhook_secret.encode(), row[0], hashlib.sha256).hexdigest())):
                raise ValueError('signed webhook unavailable')
            expected = mode_provenance(webhook_secret, delivery_id, row[0], mode[0], mode[1]) if mode else None
            if not mode or mode[0] != 1 or not expected or not isinstance(mode[2], str) or not hmac.compare_digest(mode[2], expected):
                raise ValueError('invalid mode provenance')
            if not valid_result(webhook_secret, delivery_id, row[0], mode[0], mode[1], row[1], mode[3]):
                raise ValueError('invalid result provenance')
    if row is None:
        raise ValueError('completed worker result unavailable')
    try:
        event, result = map(json.loads, row)
        repo_id = event['repository']['id']
        repo = event['repository']['full_name']
        number = event['number']
        pr = event['pull_request']
        sha = pr['head']['sha']
        base = result['base_sha']
        review = result['review']
        if (event['action'] not in ACTIONS or pr['state'] != 'open' or pr['draft'] is not False
                or type(number) is not int or type(pr['number']) is not int or pr['number'] != number
                or type(repo_id) is not int or type(result['repo_id']) is not int
                or result['repo_id'] != repo_id
                or result['status'] != 'done' or result['repository'] != repo
                or type(result['number']) is not int or result['number'] != number
                or result['sha'] != sha):
            raise ValueError('worker result identity mismatch')
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise ValueError('invalid worker result or event') from exc
    publisher = GitHubPublisher(post, current, repos, enabled=enabled,
                                ledger_path=ledger_path, get=get, gate_path=gate_path,
                                single_vps_mvp=single_vps_mvp)
    if enabled and (not callable(approve) or approve(repo_id, repo, number, sha, base, review) is not True):
        raise ValueError('public release not approved')
    return publisher.publish(repo_id, repo, number, sha, review, base_sha=base)
