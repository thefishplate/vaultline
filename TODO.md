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

## Next

- [ ] **A command-line interface**: list, get, set, hint, verify, rotate.
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
- **The suite is slow** - about a minute, nearly all of it GPG subprocesses.
  The rotation tests save at each step and every save verifies by decrypting,
  which is the behaviour under test rather than overhead to remove.
- **No command-line interface yet**, so today this is a library and nothing else.
