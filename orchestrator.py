"""Continuous queue processing; publication requires explicit single-VPS opt-in."""
import argparse
import json
import os
from pathlib import Path
import signal
import threading
import sqlite3
from contextlib import closing

from github_adapter import GitHubReadOnly, app_read_auth, require_app_read_flag
from model_adapter import IsolationUnavailable, resolve_hermes_direct_adapter
from notification import DiscordNotifier, DiscordTransport
from outbox import Outbox
from repo_config import allowed
from worker import Worker
from publish_worker import publish_worker_result
from github_app_auth import InstallationAuth
from github_app_transport import installation_transport, publish_transport, review_list_transport


def _status(value):
    # Never serialize adapter exceptions, job contents, or model output.
    print(json.dumps({'status': value}), flush=True)


def deliver_notification(notifier, channel, content):
    if notifier.notify(channel, content) != 'sent':
        raise ValueError('notification not sent')


def notification_loop(outbox, notifier, channel, stop, *, poll_interval=5):
    while not stop.is_set():
        try:
            result = outbox.send_once(lambda content: deliver_notification(notifier, channel, content))
        except Exception:
            _status('notification_error')
            result = None
        if result is None:
            stop.wait(poll_interval)


def publication_loop(db, repos, github, auth, ledger, gate, secret, stop, poll_interval=5):
    # ponytail: scan completed jobs; the ledger prevents repeat POSTs after restart.
    finished = set()
    ambiguous = set()  # ponytail: log once per unresolved job; restart resets suppression.
    errors = set()  # ponytail: one error per job until recovery; restart resets suppression.
    poll_error = False
    while not stop.is_set():
        try:
            with closing(sqlite3.connect(db, timeout=5)) as conn:
                ids = [row[0] for row in conn.execute("SELECT delivery_id FROM work WHERE status='done'")]
            poll_error = False
            errors.intersection_update(ids)
            ambiguous.intersection_update(ids)
            finished.intersection_update(ids)
            for delivery in ids:
                if delivery in finished or stop.is_set():
                    continue
                def token_for_path(path):
                    repo = '/'.join(path.split('/')[2:4])
                    ident = next(i for i, name in allowed(repos).items() if name == repo)
                    return auth.token(ident, repo)[0]
                def post(path, body):
                    path = '/' + path
                    return publish_transport(token_for_path(path), path, body)
                def get(path):
                    path = '/' + path
                    return review_list_transport(token_for_path(path), path)
                try:
                    result = publish_worker_result(db, delivery, post=post, current=github.current,
                        repos=repos, get=get, ledger_path=ledger, gate_path=gate, enabled=True,
                        approve=lambda *args: True, single_vps_mvp=True, webhook_secret=secret)
                    errors.discard(delivery)
                    if result == 'sent':
                        finished.add(delivery)
                    if result != 'ambiguous' or delivery not in ambiguous:
                        _status('publication_' + result)
                    if result == 'ambiguous':
                        ambiguous.add(delivery)
                    else:
                        ambiguous.discard(delivery)
                except Exception:
                    if delivery not in errors:
                        _status('publication_error')
                        errors.add(delivery)
        except Exception:
            if not poll_error:
                _status('publication_error')
                poll_error = True
        stop.wait(poll_interval)


def run_loop(worker, stop, *, notifier=None, channel=None, poll_interval=5, max_backoff=60):
    if not 0 < poll_interval <= max_backoff:
        raise ValueError('invalid polling interval')
    backoff = poll_interval
    while not stop.is_set():
        try:
            result = worker.run_once()
            if result is not None and not isinstance(result, dict):
                raise ValueError('invalid worker result')
            if result is not None and not isinstance(result.get('status'), str):
                raise ValueError('invalid worker status')
        except Exception:
            _status('worker_error')
            stop.wait(backoff)
            backoff = min(max_backoff, backoff * 2)
            continue
        backoff = poll_interval
        if result is None:
            stop.wait(poll_interval)
            continue
        status = result.get('status')
        _status(status if status in {'done', 'skipped', 'retry', 'failed', 'lease_lost'} else 'unknown')
        if status == 'done' and notifier is not None:
            try:
                notifier.notify(channel, 'PR review completed (dry run).')
            except Exception:
                _status('notification_error')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Process reviews; publication requires explicit opt-in.')
    parser.error = lambda message: parser.exit(2, 'error: invalid arguments\n')
    parser.add_argument('--db', required=True)
    parser.add_argument('--wiki', required=True)
    parser.add_argument('--repos', required=True)
    parser.add_argument('--dry-run', action='store_true', help='acknowledge GitHub publication is disabled')
    parser.add_argument('--enable-direct-inference', action='store_true')
    parser.add_argument('--authorize-wiki-transfer', action='store_true')
    parser.add_argument('--github-app-read', action='store_true', help='use locally configured GitHub App read authentication')
    parser.add_argument('--enable-discord-notifications', action='store_true', help='send completion notices using DISCORD_CHANNEL_ID and DISCORD_BOT_TOKEN')
    parser.add_argument('--single-vps-publish', action='store_true')
    parser.add_argument('--publication-ledger')
    parser.add_argument('--publication-gate')
    args = parser.parse_args(argv)
    if not ((args.dry_run != args.single_vps_publish) and args.enable_direct_inference and args.authorize_wiki_transfer):
        parser.error('select dry run or single VPS publication and authorize inference')
    if args.single_vps_publish and not (args.github_app_read and args.publication_ledger and args.publication_gate and os.environ.get('WEBHOOK_SECRET')):
        parser.error('publication configuration incomplete')
    try:
        require_app_read_flag(args.github_app_read)
        db = Path(args.db)
        if db.is_symlink() or not db.is_file():
            raise ValueError('existing queue database required')
        allowed(args.repos)
        if args.single_vps_publish and set(allowed(args.repos).values()) != {'juny0955/pr-review-bot'}:
            raise ValueError('experimental repository only')
        notifier = channel = None
        if args.enable_discord_notifications:
            channel = os.environ.get('DISCORD_CHANNEL_ID')
            transport = DiscordTransport(channel)
            notifier = DiscordNotifier([channel], transport, enabled=True)
        github = (GitHubReadOnly(args.repos, auth=app_read_auth(args.repos))
                  if args.github_app_read else GitHubReadOnly(args.repos))
        publish_auth = None
        if args.single_vps_publish:
            read_auth = github.auth
            if read_auth is None:
                raise ValueError('App authentication required')
            publish_auth = InstallationAuth(read_auth.app_id, read_auth.installation_id, read_auth.key_path,
                                            args.repos, 'publish', installation_transport)
        model = resolve_hermes_direct_adapter()
        worker = Worker(str(db), github, model, args.wiki, args.repos)
        stop = threading.Event()
        previous = {}
        def request_stop(signum, frame):
            stop.set()
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, request_stop)
            started = []
            try:
                if notifier is not None:
                    thread = threading.Thread(target=notification_loop,
                                              args=(Outbox(str(db), repos=args.repos), notifier, channel, stop))
                    thread.start()
                    started.append(thread)
                if args.single_vps_publish:
                    if publish_auth is None:
                        raise ValueError('App authentication required')
                    publication_thread = threading.Thread(target=publication_loop,
                        args=(str(db), args.repos, github, publish_auth, args.publication_ledger,
                              args.publication_gate, os.environ['WEBHOOK_SECRET'], stop))
                    publication_thread.start()
                    started.append(publication_thread)
                run_loop(worker, stop)
            finally:
                stop.set()
                for thread in started:
                    thread.join()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        return 0
    except IsolationUnavailable:
        _status('isolation_unavailable')
        return 1
    except Exception:
        _status('error')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
