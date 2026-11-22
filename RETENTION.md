# Offline retention

Stop the receiver, worker, publisher and all other writers first. Back up the queue and the authoritative publication ledger together. Verify the ledger path is the one used by the publisher and preserve it and its backups. With `WEBHOOK_SECRET` in the environment, an operator can remove one verified, at-least-seven-day-old published result:

```python
import os
from retention import cleanup_done
print(cleanup_done('/private/queue.db', '/private/ledger.db', 'delivery-id', os.environ['WEBHOOK_SECRET']))
```

`True` means the queue body, work result and signature were removed in one transaction, leaving a replay tombstone, outbox and ledger intact. The signed webhook and work result must match repository ID, name, PR number, head and base; detected, started and completed outbox events must exist, and every outbox event must be sent with the same repository identity. A webhook without a base SHA or with a base that changed before review is retained. `False` means no deletion: these checks, age or the sent v2 ledger claim could not be verified. Errors roll back the transaction. Inspect before retrying. This is deliberately one delivery per call; it does not automatically prune or reclaim SQLite disk space. Never delete or roll back the ledger to reclaim space.

Dry-run results have no durable proof that they were never published, so this operation retains them, as well as pending, failed and ambiguous publications. They need operator reconciliation; do not infer dry-run provenance merely from a missing ledger entry.
