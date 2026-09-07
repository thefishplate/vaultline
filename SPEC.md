# vaultline - format and design

Status: **the envelope is built; everything above it is not.** This records the
decisions that are settled, and marks the ones that are not.

## 1. The file

A plaintext JSON envelope wrapping GPG-armoured blobs.

```json
{
  "format": "vaultline",
  "version": 0,
  "epoch": 0,
  "hint": "the usual three words, winter variant",
  "wrappings": [
    {"kind": "passphrase", "label": null,
     "kdf": {"kdf": "scrypt", "n": 131072, "r": 8, "p": 1, "dklen": 32},
     "salt": "<base64>", "wrapped": "<armoured master key>"}
  ],
  "payload": "<armoured secrets JSON>"
}
```

The payload is encrypted under a **random 256-bit master key**, never under
anything derived from a passphrase. That is what makes the ciphertext safe to
replicate without limit: there is nothing to guess, however long an attacker
has and whatever hardware arrives.

Each wrapping holds that master key encrypted under a key-encryption key. A
passphrase wrapping derives its KEK with scrypt over a per-wrapping salt.

## 2. Settled, and unchangeable later

A published copy cannot be unpublished, so these are fixed from the first file
written:

- **`version`** - a reader that meets a newer version refuses rather than
  guessing at it.
- **`epoch`** - names which generation of wrappings a file expects, so a
  recovery years later knows which material applies.
- **Re-wrap without re-encrypt** - access changes touch only `wrappings`.
- **KDF parameters recorded per wrapping**, not assumed globally.

## 3. What the envelope may never carry

No account names, no service names, no hostnames, no counts, no timestamps of
use. The procedure may be public; the inventory may not. *How to rotate a
registrar credential* is a technique; *the registrar is X and the recovery
channel is Y* is reconnaissance.

The hint is the one deliberate exception, and it is the operator's to write. A
hint that reminds you and tells a stranger nothing is the goal; one that names
a pet and a year is most of a passphrase.

## 4. Container: GPG, not a bespoke format

GPG owns the container, the cipher and the integrity check. The line is between
building a **container** and defining a **payload schema**. The first is where
unauthenticated headers and homemade integrity checks come from, and it is not
ours to build. If a proposal requires touching the container, it has crossed
that line.

GPG also ships with Git, so a successor needs nothing bespoke: one tool to
decrypt, and then none, because what falls out is JSON.

## 5. Withdrawal is not revocation

Removing a wrapping affects **copies made afterwards, and no others.** Whoever
holds an earlier copy holds the wrapping it was written with, permanently.

**Only rotating the secret itself closes that door.** Removal is half a
withdrawal, never all of it. There is a test named for this so that nobody
later mistakes one for the other.

## 6. Not built

- **Rotation state machine.** Three outcomes, not two: rejected, *unknown*,
  accepted. Ambiguity is the dangerous case - a service that commits a change
  and loses the response must never be read as failure. Activation requires a
  fresh verified login, because acceptance of a form is not proof.
- **Threshold recovery.** A quorum wrapping alongside the passphrase one. The
  format is built for it; the policy around it - threshold, holders, what
  authorises a succession - is deliberately absent, because those are decisions
  about people and cannot sensibly be fixed before there are any.
- **Adapters, and any command-line interface.**

## 7. Open

- The threshold, when threshold recovery is built. Expensive to change once
  material has been distributed to holders.
- Whether a widely replicated copy should carry the full payload or only what
  is needed to re-establish control. Smaller replicates better.
