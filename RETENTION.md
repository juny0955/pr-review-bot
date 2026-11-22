# Offline retention

The receiver does not automatically clean up any queue item. At capacity it returns HTTP 503 for new deliveries. This procedure only removes eligible `done` results; `failed`, `skipped`, and missing or invalid provenance remain retained and need operator investigation. It cannot guarantee capacity recovery.

Stop the receiver, worker, publisher and all other writers first. Back up the queue and the authoritative publication ledger together. Verify the ledger path is the one used by the publisher and preserve it and its backups. With `WEBHOOK_SECRET` in the environment, an operator can remove one verified, at-least-seven-day-old published result:

```python
import os
from retention import cleanup_done
print(cleanup_done('/private/queue.db', '/private/ledger.db', 'delivery-id', os.environ['WEBHOOK_SECRET']))
```

`True` means the queue body, work result and signature were removed in one transaction, leaving a replay tombstone, outbox and ledger intact. The signed webhook and work result must match repository ID, name, PR number, head and base; detected, started and completed outbox events must exist. Sent events must match the identity. For jobs explicitly created with notifications disabled, suppressed events may have missing identity, but any present identity must match. Pending, sending, failed and unknown events always block cleanup. A webhook without a base SHA or with a base that changed before review is retained. `False` means no deletion. Errors roll back the transaction. Inspect before retrying. This is deliberately one delivery per call; it does not automatically prune or reclaim SQLite disk space. Never delete or roll back the ledger to reclaim space.

New jobs bind publication eligibility and notification mode at first claim. Explicit dry-run results can be removed only when the authoritative ledger has no matching claim; publish-eligible results require a sent claim and valid provenance. Legacy results without provenance are retained regardless of ledger state. Pending, failed or ambiguous claims are retained. Legacy results without provenance are never treated as dry-run merely because a claim is missing. Retry jobs retain their original modes; changing modes does not upgrade existing jobs. The automatic publication loop only selects explicitly publish-eligible results. Stop and restart the existing service to load this policy; edits do not change a running Python process.

Both v2 and legacy ledger keys are checked. A genuine legacy claim blocks cleanup; the publisher's exact v2 legacy-reservation sentinel is allowed only alongside a sent v2 claim.
