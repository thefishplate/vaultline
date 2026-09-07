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

## Rotation

The failure this exists to prevent: a service accepts a new value, the record
of it is lost, and the account becomes unreachable.

Three outcomes, not two. The middle one is the reason this is a state machine:

```
begin_rotation()   candidate written to disk BEFORE it is submitted
                   - a crash afterwards leaves both values, and a superset
                     is recoverable where an empty set is not

record_outcome()   rejected  demonstrably refused before being applied
                             -> discard the candidate; the old value stands
                   unknown   timeout, 5xx, dropped connection
                             -> KEEP BOTH. Never delete.
                   accepted  the form was taken - which is not activation,
                             because services truncate and normalise

verify()           ask the service which value it accepts.
                   candidate works        -> it becomes the value
                   candidate fails, old works -> the change never took
                   neither works          -> stop, delete nothing, alarm
                   could not tell         -> learn nothing, change nothing
```

The verifier returns True, False or **None**. A network failure is not evidence
either way, and treating it as evidence is the same mistake as treating an
ambiguous submission as failure.

**The vault draws the conclusion; the verifier supplies only a fact.** An
adapter that could report success on its own authority could talk the vault
into retiring a working credential.

**Retry limits are part of correctness.** A wrong guess can lock an account, so
a verification budget is enforced and falling back to test the old value spends
from it. When the budget runs out the tool stops rather than trying once more.

## Getting a credential into a login form

The lowest-risk option, and the only one implemented: the tool holds the value,
you paste it.

```python
v.to_clipboard("REGISTRAR")        # blocks, counts down, takes it back
```

```
  REGISTRAR is on the clipboard. Paste it now.
  clearing in 24s   Ctrl-C to clear now
  cleared.
```

No browser is driven and no form is filled, so there is nothing here a service
could object to - while the part that actually hurts, finding and retyping a
long random string, is gone.

Three details that are not incidental:

- **It blocks.** A background timer does not survive the process exiting, so a
  call that copied and returned would leave the value on the clipboard
  indefinitely while appearing to have cleaned up. Ctrl-C clears early rather
  than skipping the clear.
- **It will not wipe something you copied since.** If the clipboard has changed
  it is left alone, and it says so.
- **The value is never printed, returned or logged.** What comes back is what
  happened, not what was copied.

> **The clear is a courtesy, not a control.** Any process running as you can
> read the clipboard at any moment. On Windows, if clipboard history is on the
> value stays in Win+V after the clipboard is emptied, and if cloud sync is on
> it has already left the machine. vaultline checks and warns, because a timed
> clear that removes nothing is worse than no clear at all - it buys confidence
> without buying safety.

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

None, in the Python sense. `gpg` must be findable, and key stretching uses
`hashlib.scrypt`, which is standard library.

GPG ships with Git and with every Linux distribution. On Windows there is a
catch worth knowing: Git adds it to PATH **only inside Git Bash**, so a
PowerShell or cmd session will not see it. vaultline therefore looks on PATH
first, then in the usual install locations, and you can point it anywhere with
`VAULTLINE_GPG`. If none of that works it says so, and says what to do.

GPG's own S2K is not memory-hard, so the passphrase is stretched with scrypt
first and GPG only ever sees a high-entropy string. The parameters are recorded
in each file rather than assumed, so a file written today opens in ten years
without the reader having to know what the defaults were then.

## Status

**Pre-alpha.** Implemented and covered by 67 tests: the envelope, wrappings,
saving, location safety, the rotation state machine, and the clipboard tier.
Not implemented: adapters that talk to services, threshold recovery, and any
command-line interface.

Nothing is published to PyPI yet.

## Running the tests

```
python vaultline_dev.py             # 67 tests
python vaultline_dev.py test --fast # skip the real-KDF case
```

Clipboard tests skip where there is no clipboard, so a headless runner reports
them as skipped rather than passing without having tested anything.

Nearly all of that minute is GPG subprocesses. The rotation tests are slow
because the state machine saves at each step, and each save encrypts and then
decrypts again to check the write survived - which is the behaviour being
tested, so it is not something to optimise away.

The suite uses deliberately weak KDF parameters so that it finishes; one test
exercises the shipped parameters, because a suite that only tests the cheap
path is not testing what ships.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
