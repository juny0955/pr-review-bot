"""Continuous queue processing: local results only, no GitHub publication."""
import argparse
import json
import os
from pathlib import Path
import signal
import threading

from github_adapter import GitHubReadOnly
from model_adapter import resolve_hermes_direct_adapter
from notification import DiscordNotifier, DiscordTransport
from outbox import Outbox
from repo_config import allowed
from worker import Worker


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
    parser = argparse.ArgumentParser(description='Continuously process reviews without publishing to GitHub.')
    parser.add_argument('--db', required=True)
    parser.add_argument('--wiki', required=True)
    parser.add_argument('--repos', required=True)
    parser.add_argument('--dry-run', action='store_true', help='acknowledge GitHub publication is disabled')
    parser.add_argument('--enable-direct-inference', action='store_true')
    parser.add_argument('--authorize-wiki-transfer', action='store_true')
    parser.add_argument('--enable-discord-notifications', action='store_true', help='send completion notices using DISCORD_CHANNEL_ID and DISCORD_BOT_TOKEN')
    args = parser.parse_args(argv)
    if not (args.dry_run and args.enable_direct_inference and args.authorize_wiki_transfer):
        parser.error('requires --dry-run, --enable-direct-inference and --authorize-wiki-transfer')
    try:
        db = Path(args.db)
        if db.is_symlink() or not db.is_file():
            raise ValueError('existing queue database required')
        allowed(args.repos)
        notifier = channel = None
        if args.enable_discord_notifications:
            channel = os.environ.get('DISCORD_CHANNEL_ID')
            transport = DiscordTransport(channel)
            notifier = DiscordNotifier([channel], transport, enabled=True)
        github = GitHubReadOnly(args.repos)
        model = resolve_hermes_direct_adapter()
        worker = Worker(str(db), github, model, args.wiki, args.repos)
        stop = threading.Event()
        previous = {}
        def request_stop(signum, frame):
            stop.set()
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, request_stop)
            thread = None
            if notifier is not None:
                thread = threading.Thread(target=notification_loop,
                                          args=(Outbox(str(db), repos=args.repos), notifier, channel, stop))
                thread.start()
            try:
                run_loop(worker, stop)
            finally:
                stop.set()
                if thread is not None:
                    thread.join()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        return 0
    except Exception:
        _status('error')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
