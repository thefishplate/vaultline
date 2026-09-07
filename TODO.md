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

## Next

- [ ] **Rotation state machine.** Three outcomes: rejected, unknown, accepted.
      Ambiguity is the dangerous case and must never be read as failure.
      Activation requires a fresh verified login. Retry limits are part of
      correctness, because a check that triggers lockout has destroyed access
      while testing whether access works.
- [ ] **A command-line interface**: list, get, set, hint, verify.
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
- **The suite is slow** - about 18 seconds, nearly all of it GPG subprocesses.
- **No command-line interface yet**, so today this is a library and nothing else.
