"""Explicit one-shot local queue runner; never publishes or starts a listener.

The CLI uses live read-only GitHub and direct inference only with explicit
flags. Inject both adapters into run_once for offline operation and tests.
"""
import argparse
import json
from pathlib import Path

from github_adapter import GitHubReadOnly
from model_adapter import resolve_hermes_direct_adapter
from repo_config import allowed
from worker import Worker


def run_once(db_path, wiki, repos, *, github, model):
    """Process at most one queued item and persist its result in the same DB."""
    path = Path(db_path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('existing queue database required')
    return Worker(str(path), github, model, wiki, repos).run_once()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Process one queued PR without publishing.')
    parser.add_argument('--db', required=True, help='existing SQLite queue database')
    parser.add_argument('--wiki', required=True, help='wiki directory sent to the model provider')
    parser.add_argument('--repos', required=True, help='repository policy JSON')
    parser.add_argument('--dry-run', action='store_true', help='acknowledge local result only; never publish')
    parser.add_argument('--enable-direct-inference', action='store_true', help='authorize a real provider request')
    parser.add_argument('--authorize-wiki-transfer', action='store_true', help='authorize sending wiki evidence and diff to provider')
    args = parser.parse_args(argv)
    if not (args.dry_run and args.enable_direct_inference and args.authorize_wiki_transfer):
        parser.error('requires --dry-run, --enable-direct-inference and --authorize-wiki-transfer')
    try:
        if Path(args.db).is_symlink() or not Path(args.db).is_file():
            raise ValueError('existing queue database required')
        allowed(args.repos)
        github = GitHubReadOnly(args.repos)
        model = resolve_hermes_direct_adapter()
        result = run_once(args.db, args.wiki, args.repos, github=github, model=model)
        print(json.dumps({'status': result['status'] if result else 'idle'}))
        return 1 if result and result['status'] in ('retry', 'failed', 'lease_lost') else 0
    except Exception:
        # Paths, provider errors and other exception strings may contain secrets.
        print(json.dumps({'status': 'error'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
