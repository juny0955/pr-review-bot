"""Continuous queue processing; publication requires explicit single-VPS opt-in."""
import argparse
import json
import os
from pathlib import Path
import signal
import threading
import time
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
from github_app_transport import installation_transport, inventory_transport, publish_transport, review_list_transport
from installation_inventory import reconcile_installation, SyncSuperseded


def _status(value, *, stage=None, error=None):
    # Never serialize adapter exceptions, job contents, or model output.
    data = {'status': value}
    if stage is not None:
        # ponytail: exact types only; custom exception names can contain secrets.
        kinds = ((ValueError, 'ValueError'), (RuntimeError, 'RuntimeError'),
                 (OSError, 'OSError'), (TimeoutError, 'TimeoutError'),
                 (sqlite3.OperationalError, 'OperationalError'),
                 (sqlite3.IntegrityError, 'IntegrityError'))
        data.update(stage=stage, exception=next((name for kind, name in kinds if type(error) is kind), 'other'))
    print(json.dumps(data), flush=True)


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


def inventory_loop(auth, gate, repos, stop, poll_interval=60, *, failed=None):
    while not stop.wait(poll_interval):
        try:
            reconcile_installation(auth, inventory_transport, gate, repos)
        except SyncSuperseded:
            continue
        except Exception as error:
            if failed is not None:
                failed.set()
            stop.set()
            try:
                _status('inventory_error', stage='inventory', error=error)
            except OSError:
                pass
            return


def publication_loop(db, repos, github, auth, ledger, gate, secret, stop, poll_interval=5):
    # ponytail: scan completed jobs; the ledger prevents repeat POSTs after restart.
    finished = set()
    ambiguous = set()  # ponytail: log once per unresolved job; restart resets suppression.
    errors = set()  # ponytail: one error per job until recovery; restart resets suppression.
    retries = {}  # ponytail: in-memory backoff resets on restart; persist only if needed.
    poll_error = False
    while not stop.is_set():
        try:
            with closing(sqlite3.connect(db, timeout=5)) as conn:
                ids = [row[0] for row in conn.execute("SELECT delivery_id FROM work WHERE status='done' AND publish_eligible=1")]
            poll_error = False
            errors.intersection_update(ids)
            ambiguous.intersection_update(ids)
            finished.intersection_update(ids)
            retries = {key: value for key, value in retries.items() if key in ids}
            for delivery in ids:
                if delivery in finished or stop.is_set():
                    continue
                now = time.monotonic()
                if delivery in retries and now < retries[delivery][0]:
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
                        approve=lambda *args: True, single_vps_mvp=True, webhook_secret=secret, diff=github.diff)
                    errors.discard(delivery)
                    if result == 'sent':
                        finished.add(delivery)
                    if result != 'ambiguous' or delivery not in ambiguous:
                        _status('publication_' + result)
                    if result == 'ambiguous':
                        ambiguous.add(delivery)
                        delay = retries.get(delivery, (0, poll_interval / 2))[1]
                        delay = min(300, max(poll_interval, delay * 2))
                        retries[delivery] = (time.monotonic() + delay, delay)
                    else:
                        ambiguous.discard(delivery)
                        retries.pop(delivery, None)
                except Exception as error:
                    if delivery in ambiguous:
                        delay = min(300, retries[delivery][1] * 2)
                        retries[delivery] = (time.monotonic() + delay, delay)
                    if delivery not in errors:
                        _status('publication_error', stage='job', error=error)
                        errors.add(delivery)
        except Exception as error:
            if not poll_error:
                _status('publication_error', stage='poll', error=error)
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
    parser.add_argument('--sync-installation', action='store_true', help='sync public installation repositories at startup and every 60 seconds')
    args = parser.parse_args(argv)
    if not ((args.dry_run != args.single_vps_publish) and args.enable_direct_inference and args.authorize_wiki_transfer):
        parser.error('select dry run or single VPS publication and authorize inference')
    if args.single_vps_publish and not (args.github_app_read and args.publication_ledger and args.publication_gate and os.environ.get('WEBHOOK_SECRET')):
        parser.error('publication configuration incomplete')
    if args.sync_installation and not (args.github_app_read and args.publication_gate):
        parser.error('installation sync requires App read and a gate')
    try:
        if not os.environ.get('WEBHOOK_SECRET'):
            raise ValueError('webhook secret required')
        require_app_read_flag(args.github_app_read)
        db = Path(args.db)
        if db.is_symlink() or not db.is_file():
            raise ValueError('existing queue database required')
        repos = allowed(args.repos)
        if args.single_vps_publish and not repos and not args.sync_installation:
            raise ValueError('at least one repository required')
        notifier = channel = None
        if args.enable_discord_notifications:
            channel = os.environ.get('DISCORD_CHANNEL_ID')
            transport = DiscordTransport(channel)
            notifier = DiscordNotifier([channel], transport, enabled=True)
        github = (GitHubReadOnly(args.repos, auth=app_read_auth(args.repos))
                  if args.github_app_read else GitHubReadOnly(args.repos))
        if args.sync_installation:
            try:
                reconcile_installation(github.auth, inventory_transport, args.publication_gate, args.repos)
            except SyncSuperseded:
                pass  # The periodic reconciler retries; the gate remains paused.
        publish_auth = None
        if args.single_vps_publish:
            read_auth = github.auth
            if read_auth is None:
                raise ValueError('App authentication required')
            publish_auth = InstallationAuth(read_auth.app_id, read_auth.installation_id, read_auth.key_path,
                                            args.repos, 'publish', installation_transport)
        model = resolve_hermes_direct_adapter()
        worker = Worker(str(db), github, model, args.wiki, args.repos,
                        publish_eligible=args.single_vps_publish,
                        notifications_enabled=args.enable_discord_notifications,
                        webhook_secret=os.environ.get('WEBHOOK_SECRET'))
        stop = threading.Event()
        inventory_failed = threading.Event()
        previous = {}
        def request_stop(signum, frame):
            stop.set()
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, request_stop)
            started = []
            try:
                if args.sync_installation:
                    inventory_thread = threading.Thread(target=inventory_loop,
                        args=(github.auth, args.publication_gate, args.repos, stop),
                        kwargs={'failed': inventory_failed})
                    inventory_thread.start()
                    started.append(inventory_thread)
                if notifier is not None:
                    thread = threading.Thread(target=notification_loop,
                                              args=(Outbox(str(db), repos=args.repos, webhook_secret=os.environ.get('WEBHOOK_SECRET')), notifier, channel, stop))
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
        return 1 if inventory_failed.is_set() else 0
    except IsolationUnavailable:
        _status('isolation_unavailable')
        return 1
    except Exception:
        _status('error')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
