# vaultline

A credential store whose ciphertext is safe to publish, and whose access can be
re-wrapped without re-encrypting anything.

```
plaintext JSON envelope      version, epoch, KDF parameters, a hint
  wrappings[]                the master key, encrypted several ways
  payload                    the secrets, encrypted under the master key
```

Most secret managers say *protect the encrypted database*. This says the
opposite: replicate it, deliberately, as widely as you like. That is only a
sane thing to say if the payload key is random rather than remembered - so it
is.

## The two properties

**Re-wrapping is not re-encryption.** Granting or withdrawing a way in encrypts
32 bytes and appends a record. The payload ciphertext is byte-identical
afterwards, so a file already copied to a dozen places does not have to be
redistributed because somebody was granted access. Adding threshold recovery
later is additive rather than a migration.

**The envelope is readable without the key.** It carries the format version,
the KDF parameters, how many ways in there are, and an optional hint - and no
inventory. Not the account names, not how many there are, not which services.
That is the reconnaissance, and it stays inside the payload. A passphrase
reminder that requires the passphrase to read is not a reminder.

## What it is not

- **Not a password manager.** No browser extension, no autofill, no sync
  service, no phone app.
- **Not novel cryptography.** GPG owns the container, the cipher and the
  integrity check; it is invoked as a subprocess and never imported. What is
  here is an envelope schema and a workflow.
- **Not finished.** See Status.

## Prior art

If your situation is in the right-hand column, use that instead - those are
more mature, more reviewed and better supported than this.

| If you need | Use |
|---|---|
| A password manager with apps, sync and autofill | Bitwarden, 1Password, KeePassXC |
| Secrets for a running fleet, with leasing and audit | HashiCorp Vault, cloud secret managers |
| Encrypted files inside a git repository | SOPS, git-crypt, age |
| Splitting a key among several holders | an established Shamir implementation |

What none of them combine is a file you are *encouraged* to replicate, whose
access list changes without touching the ciphertext, and whose envelope tells a
finder how to open it while telling them nothing about what is inside.

## Dependencies

None, in the Python sense. `gpg` must be on PATH - it ships with Git, and with
every Linux distribution - and key stretching uses `hashlib.scrypt`, which is
standard library.

GPG's own S2K is not memory-hard, so the passphrase is stretched with scrypt
first and GPG only ever sees a high-entropy string. The parameters are recorded
in each file rather than assumed, so a file written today opens in ten years
without the reader having to know what the defaults were then.

## Status

**Pre-alpha.** The envelope, wrapping, saving and location safety are
implemented and covered by 34 tests. Not implemented: the rotation state
machine, threshold recovery, adapters, and any command-line interface.

Nothing is published to PyPI yet.

## Running the tests

```
python vaultline_dev.py             # 34 tests, about 18 seconds
python vaultline_dev.py test --fast # skip the real-KDF case
```

The suite uses deliberately weak KDF parameters so that it finishes; one test
exercises the shipped parameters, because a suite that only tests the cheap
path is not testing what ships.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
