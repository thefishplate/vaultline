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
- **`GithubSshKeyAdapter`**, the first adapter against a published API:
  create-then-revoke over `/user/keys`. A bad authorising token reports `None`
  rather than `False`, because it says nothing about the key being asked
  about. Personal access tokens are unsupported - GitHub has no endpoint that
  creates one.
- **Playbooks**: a declarative format for how to perform an operation at a
  site, with `validate_playbook()` and a pure `plan()`. The origin comes from
  the credential rather than the playbook, inventory keys are refused by name,
  unknown keys are an error rather than ignored, and the vocabulary has no
  conditionals, loops, waits or retries. Plans carry roles rather than values,
  so they are safe to log.
- **A read-only transport.** `Transport(readonly=True)` refuses mutating
  methods, so an adapter can share code between `verify` and `submit` and
  still be unable to change anything while verifying. The escape hatch for
  genuinely side-effect-free POSTs demands a written reason. The contract
  asserts every adapter verifies read-only, and an adapter that mutates during
  verification is kept in the suite to prove the check catches it.
- **Transport, fault injection and the adapter contract.** `Transport` is the
  only route to the network; `FAILURE_SHAPES` enumerates thirteen ways a
  service fails or changes, each declaring what an adapter may conclude; and
  the contract runs every adapter against every shape. A deliberately wrong
  adapter is in the suite, with a test asserting the contract rejects it.
- Fault injection lives in the shipped module rather than a test harness, so
  it can be used against a real service on purpose. It can only make the
  system more cautious - no shape produces a success - and `Vault.verify`
  refuses to run while it is armed.
- `injection_points()`, parsed from the source with `ast`, plus tests proving
  the declared table and the call sites agree in both directions and that
  every point is exercised.
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
- 138 tests, including one asserting that adding a wrapping leaves the payload
  byte-identical, and one asserting that an older copy still opens after a
  wrapping has been removed.

Nothing is published to PyPI yet.
