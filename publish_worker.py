"""Publish a stored worker result by delivery ID, independently of notifications.

The approval callback is only an additional veto, never evidence for the gate.
Live publication is disabled until operational isolation is implemented and verified.
Queue retention may delete old results, which then fail closed.
"""
from contextlib import closing
import json
import sqlite3

from publisher import GitHubPublisher
from worker import ACTIONS


def publish_worker_result(db_path, delivery_id, *, post, current, repos, get=None,
                          ledger_path=None, enabled=False, approve=None, gate_path=None):
    if type(enabled) is not bool:
        raise ValueError('enabled must be boolean')
    with closing(sqlite3.connect(db_path, timeout=5)) as db:
        row = db.execute('''SELECT q.body, w.result FROM queue q JOIN work w
            ON w.delivery_id=q.delivery_id WHERE q.delivery_id=? AND w.status='done' ''',
                         (delivery_id,)).fetchone()
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
                                ledger_path=ledger_path, get=get, gate_path=gate_path)
    if enabled and (not callable(approve) or approve(repo_id, repo, number, sha, base, review) is not True):
        raise ValueError('public release not approved')
    return publisher.publish(repo_id, repo, number, sha, review, base_sha=base)
