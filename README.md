# Local PR webhook intake prototype

Experimental Python prototype. Receives signed GitHub `pull_request` payloads on `127.0.0.1`, checks a repository ID and name allowlist, and persists the raw payload to SQLite before acknowledging. Offline tests use the standard library; optional experimental adapters can access GitHub and a model provider. No production deployment or public endpoint is included.

## Run

Copy `repos.example.json` to the ignored `repos.json` and configure repository IDs and names as described in `CONFIG.md`. Set a strong secret through secure environment management. Do not commit secrets or use a production secret for experiments.

```sh
export WEBHOOK_SECRET  # supply via your secret manager or secure prompt
export REPO_CONFIG='./repos.json'
export QUEUE_DB='./queue.sqlite3'  # optional
export PORT=8080                  # optional
python3 receiver.py
```

Run tests with `python3 -m unittest -v`.

`POST /webhook` accepts a maximum 1 MiB body, validates `X-Hub-Signature-256` over the exact bytes, checks the event, repository, supported action and PR fields, then inserts in a serialized transaction. A first delivery returns 202; a byte-identical repeat returns 200 even with a different delivery ID; a reused ID with different bytes returns 409. Unsupported events and malformed requests are rejected. At 1,000 queue rows new bodies return 503, while duplicates remain acknowledged. Entries are not automatically removed. The DB is created or restricted to mode 0600 and must not be a symlink; use a private, trusted directory and protect sidecars and backups. Payloads may contain sensitive repository data.

## Offline worker

`worker.Worker(db_path, github, model, wiki, repos)` processes one existing delivery with `run_once()`. Only inject trusted test doubles: `github.current(repo, number)` returns `state`, boolean `draft`, and `sha`; `github.diff(repo, number, sha)` returns text; `model.review(request)` returns text. See `test_worker.py` for runnable examples. Set the wiki path to your own vault; tests use temporary fixtures. The request labels the intended profile `prreview` and model `gpt-6.1-terra`, but does not start Hermes or enforce profile isolation. Results are local JSON in SQLite `work.result`; no review is posted. The worker never checks out, imports, or executes PR code.

Only configured repositories, open non-draft eligible events and exact 40-character head SHAs are accepted. Current PR state is checked before and after the review. Claims are serialized, leased and fenced; failures retry and expired claims can be recovered. Processing is at-least-once: lease expiration can duplicate adapter calls. Each delivery has at most three claims, including expired leases. Retry delays are 30 and 60 seconds, persisted in SQLite; an expired lease's delay starts at expiry. After the final failure or expired final lease, the row becomes `failed` and requires operator intervention. Existing retry rows from the previous schema are immediately eligible unless already exhausted. Delayed rows do not block later eligible deliveries. Timing relies on a consistent wall clock. The final freshness check is not atomic with subsequent changes. Wiki retrieval reads the `wiki/` article directory within the configured vault, or the configured directory itself if it has no `wiki` entry. It includes `index.md` when readable, scans at most 500 directory entries, ranks readable top-level Markdown by keyword overlap with the diff, and returns at most 20 files with paths relative to the configured root. Files over 16 KiB, invalid UTF-8, and symlinks are excluded; a symlinked `wiki/` directory is rejected. This simple ranking can miss relevant material, especially beyond the scan limit. Wiki contents and PR text are untrusted. Protect the SQLite DB, sidecars and directory; results may be sensitive.

**Do not connect a real model or GitHub adapter to the worker yet.** No sandbox or prompt-injection isolation is implemented, and arbitrary injected adapters can execute code or access networks. No production scheduler, post mechanism, retention or monitoring is provided. Automated posting would additionally require an atomic freshness strategy and authorization design.

`model_adapter.DirectInferenceAdapter` is an opt-in experimental direct client adapter, separate from the fail-closed `LocalOnlyModelAdapter`. `resolve_hermes_direct_adapter()` uses the installed Hermes auxiliary client with the explicit `openai-codex` provider and `gpt-6.1-terra`; it does not launch an agent or supply tools. It sends diff and wiki data to the provider, so use only with authorization. Output is untrusted and must not be posted automatically. No OS credential separation or prompt-injection protection is implied. Input and accepted output are size-limited; the Hermes Codex transport omits the requested token limit, so generation itself is not token-bounded (the request has a timeout). The resolver depends on an installed Hermes environment and configured credentials; tests inject a client and do not require either.

## Limitations

Localhost is not an authentication boundary against other local users. GitHub signs the body, not delivery/event headers. Exact-body deduplication lasts only while the corresponding queue row remains; deleting rows or replacing the DB permits replay. Legitimately identical bodies are also collapsed, and the unsigned event header cannot establish event provenance. The row cap bounds queued body bytes but not SQLite overhead, worker results, existing oversized databases, HTTP threads, or filesystem use; a full queue requires careful operator intervention, which can weaken replay protection. The database directory must be private: the path is reopened by SQLite, and sidecars and backups need protection. HTTP has no TLS, and the built-in server and SQLite queue are not hardened for internet exposure, hostile local clients, or high traffic. A real GitHub webhook cannot reach localhost directly; do not expose this prototype publicly. No inbound traffic is generated by the project itself.
