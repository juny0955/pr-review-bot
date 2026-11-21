# Continuous dry-run worker

This is an explicitly started process, not a service installer. It consumes the existing SQLite queue, stores reviews locally, and never invokes the GitHub publisher. Dry-run does **not** mean offline: the explicit inference flags authorize transmitting PR diffs and wiki evidence to the configured model provider, and GitHub is read over the network. Follow the GitHub adapter's scratch and authentication setup in README.md first.

```
python orchestrator.py --db /path/to/queue.db --wiki /path/to/wiki --repos /path/to/repos.json \
  --dry-run --enable-direct-inference --authorize-wiki-transfer
```

To additionally send Discord messages, configure `DISCORD_CHANNEL_ID` and `DISCORD_BOT_TOKEN` in the process environment and add `--enable-discord-notifications`. This is an external write, even in dry-run mode. Do not put credentials in command arguments or source. Notices contain only a fixed completion message, not the review or PR details. Delivery is best effort: failures are logged without details and are not retried; a crash after the result is persisted can lose a notification. Consult the local database for authoritative results.

The loop backs off on worker errors, polls when idle, and handles SIGINT/SIGTERM by finishing the current operation before stopping. Adapter calls may take time to finish. Per-job retry scheduling is persisted by the worker. Logs contain statuses only, not exception text or review contents.
