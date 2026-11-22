import hashlib
import multiprocessing as mp
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from publisher import GitHubPublisher
from revocation_gate import update_gate, gate_snapshot, locked_gate

ID, REPO, HEAD, BASE = 12, 'owner/repo', 'a' * 40, 'b' * 40
ENTRY = [ID, REPO, 1, HEAD, BASE, hashlib.sha256(b'review').hexdigest()]

def crash_locked(path, ready):
    with locked_gate(path):
        ready.set()
        os._exit(7)


def crash_post(path):
    def die(*args): os._exit(8)
    current = lambda *args: {'repo_id': ID, 'repo': REPO, 'state': 'open', 'draft': False, 'sha': HEAD, 'base_sha': BASE}
    with patch('publisher._require_operational_isolation'):
        GitHubPublisher(die, current, {ID: REPO}, enabled=True, ledger_path=path / 'ledger',
                        get=lambda *args: [], gate_path=path).publish(ID, REPO, 1, HEAD, 'review', base_sha=BASE)


def revoke(path, started, done, policy_revoke=False):
    started.set()
    update_gate(path, {} if policy_revoke else {str(ID): REPO}, [ENTRY] if policy_revoke else [], expected=gate_snapshot(path)[1])
    done.set()

class GateTests(unittest.TestCase):
    def setUp(self):
        if self._testMethodName != 'test_valid_gate_cannot_enable_real_publication':
            isolation = patch('publisher._require_operational_isolation')
            isolation.start()
            self.addCleanup(isolation.stop)
        self.tmp = tempfile.TemporaryDirectory(dir=os.path.expanduser('~'))
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        (self.path / 'lock').touch(mode=0o600)
        update_gate(self.path, {str(ID): REPO}, [ENTRY])
        self.post = Mock()
        self.current = Mock(return_value={'repo_id': ID, 'repo': REPO, 'state': 'open', 'draft': False, 'sha': HEAD, 'base_sha': BASE})
        self.pub = GitHubPublisher(self.post, self.current, {ID: REPO}, enabled=True, ledger_path=self.path / 'ledger', get=Mock(return_value=[]), gate_path=self.path)

    def publish(self, review='review', base=BASE):
        return self.pub.publish(ID, REPO, 1, HEAD, review, base_sha=base)

    def test_evidence_and_revocation(self):
        with self.assertRaises(ValueError): self.publish('different')
        with self.assertRaises(ValueError): self.publish(base='c' * 40)
        update_gate(self.path, {}, [ENTRY], expected=gate_snapshot(self.path)[1])
        with self.assertRaises(ValueError): self.publish()
        update_gate(self.path, {str(ID): REPO}, [], expected=gate_snapshot(self.path)[1])
        with self.assertRaises(ValueError): self.publish()
        self.post.assert_not_called()

    def test_post_holds_lock_across_process_revocation(self):
        for policy_revoke in (False, True):
            with self.subTest(policy_revoke=policy_revoke):
                update_gate(self.path, {str(ID): REPO}, [ENTRY], expected=gate_snapshot(self.path)[1])
                # Each case needs an unclaimed review.
                self.pub.ledger_path = self.path / ('ledger-policy' if policy_revoke else 'ledger-approval')
                # A fork would inherit the held flock and keep it alive in the child.
                ctx = mp.get_context('spawn')
                started, done = ctx.Event(), ctx.Event()
                proc = ctx.Process(target=revoke, args=(self.path, started, done, policy_revoke))
                def post(*args):
                    proc.start()
                    self.assertTrue(started.wait(3))
                    self.assertFalse(done.wait(.3))
                self.post.side_effect = post
                try:
                    self.assertEqual(self.publish(), 'sent')
                    proc.join(3)
                    self.assertEqual(proc.exitcode, 0)
                    self.assertTrue(done.is_set())
                    with self.assertRaises(ValueError): self.publish()
                finally:
                    if proc.pid is not None:
                        if proc.is_alive(): proc.terminate()
                        proc.join()

    def test_evidence_identity_and_malformed_state(self):
        for index, value in ((0, 13), (1, 'other/repo'), (2, 2), (3, 'c' * 40), (4, 'c' * 40), (5, 'f' * 64)):
            with self.subTest(index=index):
                entry = ENTRY.copy(); entry[index] = value
                update_gate(self.path, {str(ID): REPO}, [entry], expected=gate_snapshot(self.path)[1])
                with self.assertRaises(ValueError): self.publish()
        (self.path / 'state.json').write_text('{"policy":{},"approvals":[]}', encoding='utf-8')
        with self.assertRaises(ValueError): self.publish()
        self.post.assert_not_called()

    def test_crash_releases_lock_and_post_is_not_retried(self):
        ready = mp.Event()
        p = mp.Process(target=crash_locked, args=(self.path, ready))
        p.start(); p.join(3)
        self.assertEqual(p.exitcode, 7)
        self.assertTrue(ready.is_set())
        with locked_gate(self.path, timeout=.2): pass
        p = mp.Process(target=crash_post, args=(self.path,))
        p.start(); p.join(3)
        self.assertEqual(p.exitcode, 8)
        self.assertEqual(self.publish(), 'ambiguous')
        self.post.assert_not_called()

    def test_conflict_timeout_exception_and_legacy(self):
        _, version = gate_snapshot(self.path)
        update_gate(self.path, {}, [], expected=version)
        with self.assertRaisesRegex(ValueError, 'conflict'):
            update_gate(self.path, {str(ID): REPO}, [ENTRY], expected=version)
        update_gate(self.path, {str(ID): REPO}, [ENTRY], expected=gate_snapshot(self.path)[1])
        with locked_gate(self.path):
            with self.assertRaises(TimeoutError):
                with locked_gate(self.path, timeout=.05): pass
        self.current.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): self.publish()
        self.current.side_effect = None
        self.post.side_effect = TimeoutError()
        self.assertEqual(self.publish(), 'ambiguous')
        self.assertEqual(self.publish(), 'ambiguous')
        self.assertEqual(self.post.call_count, 1)
        self.pub.gate_path = None
        with self.assertRaises(ValueError): self.publish()

    def test_missing_or_unsafe_gate_fails_closed(self):
        os.chmod(self.path, 0o777)
        with self.assertRaises(ValueError): self.publish()
        self.post.assert_not_called()

    def test_lock_requires_exactly_0600(self):
        for mode in (0o700, 0o400, 0o1600):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.path / 'lock', mode)
                with self.assertRaises((ValueError, PermissionError)):
                    with locked_gate(self.path): pass
        os.chmod(self.path / 'lock', 0o600)
        with locked_gate(self.path): pass

    def test_direct_locked_call_obeys_real_gate(self):
        update_gate(self.path, {str(ID): REPO}, [], expected=gate_snapshot(self.path)[1])
        with self.assertRaisesRegex(ValueError, 'not approved'):
            self.pub._publish_locked(ID, REPO, 1, HEAD, 'review', BASE)
        self.current.assert_not_called()
        self.post.assert_not_called()
        update_gate(self.path, {str(ID): REPO}, [ENTRY], expected=gate_snapshot(self.path)[1])
        self.assertEqual(self.pub._publish_locked(ID, REPO, 1, HEAD, 'review', BASE), 'sent')
        self.post.assert_called_once()

    def test_valid_gate_cannot_enable_real_publication(self):
        with self.assertRaisesRegex(ValueError, 'operational isolation'):
            self.publish()
        with self.assertRaisesRegex(ValueError, 'operational isolation'):
            self.pub._publish_locked(ID, REPO, 1, HEAD, 'review', BASE)
        self.current.assert_not_called()
        self.post.assert_not_called()

if __name__ == '__main__': unittest.main()
