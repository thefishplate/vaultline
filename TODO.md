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

- [x] **Payload v2**: per-secret records with origin, so a playbook can be
      checked against a credential.
- [x] **First adapter**: GitHub SSH keys, create-then-revoke.
- [x] **Playbook schema, validator and planner.** The decision layer, testable
      with no browser.
- [x] **Read-only transport**, so rehearsing against a real account is a
      property of the object rather than a promise about the code.
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
- [ ] **Confirm the adapter against the live API once**, with a token carrying
      only `admin:public_key`, and record `last_verified`. Until then it is
      provably well-behaved and unproven-correct.
- [ ] **`propose()`**: generate an SSH keypair via ssh-keygen. Left out
      deliberately - a private key on disk needs its own careful pass over
      permissions and deletion, and bundling it here would have rushed it.
- [ ] **The password-rules parser and candidate generator**, over Apple's
      MIT-licensed `password-rules.json`. Bracket-aware: character classes
      contain semicolons and commas, so splitting on them silently produces
      wrong rules and a candidate the service rejects.
- [ ] **Executors**: clipboard first, then CDP. Same planner, different back
      end.
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

- **`verify` proves a key is registered, not that SSH authentication works.**
  Proving the latter means running ssh, which is outside the transport and
  would need its own injection point.
- **Withdrawal is not revocation.** Removing a wrapping affects only copies made
  afterwards. Only rotating the secret closes the door on older copies.
- **Plaintext cannot be reliably erased from memory** in a managed runtime.
- **The clipboard is readable by any process running as you**, and the timed
  clear does not remove anything Windows has already put in clipboard history
  or synced to another device. vaultline warns; it cannot fix this.
- **The suite is slow** - about a hundred seconds, nearly all of it GPG subprocesses.
  The rotation tests save at each step and every save verifies by decrypting,
  which is the behaviour under test rather than overhead to remove.
- **No command-line interface yet**, so today this is a library and nothing else.
