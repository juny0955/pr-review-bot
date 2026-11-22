# Continuous dry-run worker

The resolver requires active profile `prreview` and uses normal Hermes authentication for `gpt-6.1-terra`. This is not a security sandbox; credentials may fall back to shared state. This explicitly started process stores reviews locally and never invokes the publisher. Dry-run is not offline. The CLI uses gh only when no App environment variables exist; otherwise `--github-app-read` is required, including for empty variables. Follow README.md for scratch and authentication setup.

Startup returns `isolation_unavailable` if the required profile or model client is unavailable. Earlier failures produce an argument error or `error`. Explicit inference and wiki-transfer approvals remain required.

```
python orchestrator.py --db /path/to/queue.db --wiki /path/to/wiki --repos /path/to/repos.json \
  --dry-run --enable-direct-inference --authorize-wiki-transfer
```

To additionally send Discord messages, configure `DISCORD_CHANNEL_ID` and `DISCORD_BOT_TOKEN` in the process environment and add `--enable-discord-notifications`. This is an external write, even in dry-run mode. Do not put credentials in command arguments or source. Notices contain the event and validated repository ID, name and PR number, but no title or review contents. Identity remains in each outbox event after queue cleanup. Missing identity is recovered only when its queue body matches the current repository allowlist; unresolved or untrusted identity is held, and invalid identity is marked failed without sending. Discord mentions are disabled. Repository names are limited to 200 ASCII characters and IDs and PR numbers to positive signed 64-bit integers. They are stored transactionally in the queue database even while notifications are disabled; enabling notifications later sends the backlog. A separate polling thread delivers them while reviews run. The outbox is durable and uses a 60-second lease and at most three attempts, with 30/60-second backoff. Expired leases are retried; exhausted events remain `failed` for operator inspection. The outbox is not automatically pruned and needs disk monitoring. Retry can reorder events. Discord does not provide an exactly-once guarantee: a crash or timeout after a successful POST can produce duplicates. Consult the local database for authoritative results; protect the database and backups.

At capacity, a terminal queue item is eligible for cleanup only after all its outbox events are `sent`; pending, sending, failed, and other unsent events retain the source body and work result, regardless of identity. Recover or resolve failed and held events before cleanup. If notifications are disabled or the backlog cannot be delivered, the queue can fill and new deliveries return HTTP 503; monitor queue capacity and outbox status as well as disk usage.

The loop backs off on worker errors, polls when idle, and handles SIGINT/SIGTERM by finishing the current operation before stopping. Adapter calls may take time to finish. Per-job retry scheduling is persisted by the worker. Logs contain statuses only, not exception text or review contents.
