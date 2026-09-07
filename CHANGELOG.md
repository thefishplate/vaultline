# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, the public API may change in any minor release.

The **envelope schema** is versioned separately by `FORMAT_VERSION`, which is
written into every file. A change there is a compatibility event regardless of
what the package version does, because files already written outlive any
particular release.

## [Unreleased]

### Added
- **The clipboard tier.** `Vault.to_clipboard(name)` puts a value on the
  clipboard, blocks with a countdown, then takes it back. It blocks because a
  background timer does not survive the process exiting; it refuses to wipe
  something copied since; and it warns when Windows clipboard history is on,
  since the clear then removes nothing that mattered.
- `gpg_path()`, which looks on PATH, then the usual install locations, and
  names `VAULTLINE_GPG` and the Git Bash PATH quirk when it cannot find one.
- **The rotation state machine.** `begin_rotation`, `record_outcome`, `verify`,
  with `unknown` as a first-class outcome that keeps both values rather than
  discarding the candidate. The candidate is written to disk before it is
  submitted anywhere. Verification is core-side: the verifier returns a fact
  (True, False, or None for *could not tell*) and the vault draws the
  conclusion. Retry limits are enforced, and testing the previous value spends
  from the same budget.
- The payload became a versioned document so rotation state lives inside the
  encryption beside the values it describes. A version 0 bare mapping still
  opens and upgrades on the next save.
- The envelope: a plaintext JSON header around GPG-armoured blobs, with a
  random master key and a list of wrappings.
- `Vault.create`, `open`, `save`, `add_passphrase_wrapping`, `remove_wrapping`,
  `peek`, and the hint.
- scrypt stretching ahead of GPG, with parameters recorded per wrapping.
- Refusal to operate beneath a folder that looks like a sync root.
- Verify-then-swap saving, with a `.bak` retained.
- 67 tests, including one asserting that adding a wrapping leaves the payload
  byte-identical, and one asserting that an older copy still opens after a
  wrapping has been removed.

Nothing is published to PyPI yet.
