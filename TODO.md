# TODO

## Built

- [x] Envelope: format name, version, epoch, wrappings, payload.
- [x] Random master key, passphrase wrappings, scrypt stretching with recorded
      parameters.
- [x] Re-wrap without re-encrypt, with a test that the payload is
      byte-identical afterwards.
- [x] Refusal to write beneath a sync root, with an explicit override.
- [x] Verify-then-swap save, `.bak` retained.
- [x] `peek` - the envelope without a passphrase, carrying no inventory.

- [x] **Rotation state machine.** Three outcomes, with `unknown` keeping both
      values. Candidate persisted before submission. Verification core-side,
      with `None` for *could not tell*. Retry budget enforced, and the
      fall-back test of the previous value spends from it.
- [x] Versioned payload document, with the version 0 bare mapping still read.

- [x] **The clipboard tier.** Blocking countdown, guarded clear, clipboard
      history detection on Windows.
- [x] **gpg discovery** outside Git Bash, with an actionable error.

- [x] **Transport, fault injection, adapter contract.** Thirteen failure
      shapes, a contract with teeth, and an injection inventory proved against
      the source.

## Next

- [ ] **Verifiers for documented services.** `(value) -> True | False | None`.
      Read-only calls to published endpoints: sanctioned, safe, and the thing
      the rotation machinery already needs. This makes `verify()` real.
- [ ] **Rotators for documented services.** Prefer create-then-revoke over
      change-in-place: with tokens the new credential can be verified working
      before the old one dies, and the ambiguous window closes entirely.
- [ ] **A command-line interface**: list, get, set, hint, verify, rotate.
- [ ] **A scheduled live run against drill accounts.** The simulation covers
      the failures we imagined; only a real request notices the twelfth shape.
      Never on pull requests - a fork must not be able to reach the
      credentials.
- [ ] **An emergency sheet**, and a refusal to call a rotation complete until
      it has been regenerated. A stale sheet that looks authoritative is worse
      than none.
- [ ] **Adapters**, each declaring whether it uses a documented interface or
      drives something it was not invited to automate. Only the first kind
      belongs in this repository.

## Later

- [ ] **Threshold recovery.** A quorum wrapping beside the passphrase one. The
      format is ready; the policy is not, and cannot be until there are holders.
- [ ] A second artefact under a different key, for a successor with paper.
- [ ] Freshness checking against a hostile mirror.

## Known limits

- **Withdrawal is not revocation.** Removing a wrapping affects only copies made
  afterwards. Only rotating the secret closes the door on older copies.
- **Plaintext cannot be reliably erased from memory** in a managed runtime.
- **The clipboard is readable by any process running as you**, and the timed
  clear does not remove anything Windows has already put in clipboard history
  or synced to another device. vaultline warns; it cannot fix this.
- **The suite is slow** - about a minute, nearly all of it GPG subprocesses.
  The rotation tests save at each step and every save verifies by decrypting,
  which is the behaviour under test rather than overhead to remove.
- **No command-line interface yet**, so today this is a library and nothing else.
