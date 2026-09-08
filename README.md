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

## The first adapter

`GithubSshKeyAdapter` rotates an SSH key on a GitHub account, because those are
one of the few credentials a published API will both create and revoke:

```
POST   /user/keys        register a replacement
DELETE /user/keys/{id}   withdraw the incumbent
```

That ordering is the safe one: the replacement is confirmed working before the
incumbent is withdrawn, so the ambiguous window never opens.

**Personal access tokens are deliberately unsupported.** GitHub has no endpoint
that mints one - the `/orgs/*/personal-access-tokens` routes are for org admins
reviewing other people's. An API able to create its own credentials would be an
account-takeover primitive, so the absence is a decision, not a gap. Rotating a
PAT is manual work.

Which exposes something structural: **the credential that authorises rotation
cannot rotate itself.** This adapter needs a token carrying
`admin:public_key`, and that token has no API path of its own. Every automated
rotation scheme has a manual root, and it is usually the most privileged thing
in the store. Two consequences: the clipboard tier is permanent rather than a
stepping stone, and the root deserves to be marked as such.

## Playbooks

How to perform an operation at a site, expressed as data rather than code:

```json
{"schema_version": 0, "site": "example.com", "operation": "change_password",
 "sanction": "unsanctioned", "url": "https://example.com/settings/security",
 "fields": {"current": {"autocomplete": "current-password"},
            "new":     {"autocomplete": "new-password"}},
 "submit": {"selector": "button[type=submit]"}}
```

A playbook cannot receive the vault, cannot make an arbitrary request and
cannot execute anything. It can only say things the interpreter already
understands, which is what makes a shared or contributed playbook tenable.

**Deciding is separate from doing.** `plan()` is pure - no browser, no network,
no vault - and returns steps that name *roles* rather than carrying values, so
a plan is safe to print or log:

```
{"step": "fill", "role": "new", "source": "candidate",
 "locator": {"autocomplete": "new-password"}}
```

Four rules, and each closes something specific:

- **A playbook does not choose where a secret goes.** The origin comes from the
  credential record; a playbook whose URL leaves it is refused. A hostile
  playbook can waste your time - it cannot exfiltrate.
- **A playbook is procedure, never inventory.** No usernames, no account
  identifiers. That belongs in the encrypted payload, and keeping it out is
  what lets playbooks be shared while the vault stays private.
- **Unknown keys are an error, not ignored.** A playbook from a later schema
  may carry a constraint; an interpreter that shrugs at it runs something
  quietly less safe than the playbook claims.
- **No conditionals, no loops, no waits, no retries - ever.** Every automation
  format grows into a bad programming language; the schema forbids it. Timeouts
  are interpreter policy, so no playbook can express them. A site needing any
  of that does not get a playbook - a human does it.

The autocomplete token is preferred over a CSS selector: it is what the site
itself declares, so it does not rot when the markup is restyled.

Because deciding and doing are separate, the same interpreter serves every
tier - the clipboard tier is this planner with an executor that copies and
opens the page instead of typing.

## Adapters, and how they are tested

An adapter is handed a value and returns a fact: `True`, `False`, or `None`
for *could not tell*. **It never receives the vault** - a bad adapter should be
able to lie about one credential, not hold the store - and it never concludes.
The vault concludes.

Testing them is the hard part, because a hermetic suite runs against your own
fake, and your fake is frozen at your understanding of the service. It can
prove your code is self-consistent and can never notice that a provider
changed their API.

So the failures are simulated instead, and the assertion is not *does it still
work* - it cannot, the service changed - but **does it notice rather than
guess**:

```python
vaultline.arm("transport.request", "rate_limited")
adapter.verify(token)        # must be None. A 429 is not evidence.
```

Thirteen shapes are enumerated in `FAILURE_SHAPES`: endpoints withdrawn, auth
schemes changed, HTML where JSON was, fields renamed, truncated reads, rate
limits, timeouts. Each declares what an adapter is *allowed* to conclude, and
**no shape permits `True`** except the one where the service genuinely did
answer correctly while announcing its own retirement.

The contract runs every adapter against every shape. There is a deliberately
wrong adapter in the suite - one that treats every non-200 as a bad credential
- and a test asserting the contract **rejects** it, because a contract that
never fails anything is decoration.

### Fault injection lives in the shipped code

Not in a test harness. Failure handling you can only exercise under test is
failure handling you cannot exercise against the real world, and being able to
inject a 429 against a live service on purpose is worth more than any fake.

### Rehearsing against a real account

Risk attaches to *operations*, but code is organised by *paths* - and once
`verify` and `submit` share a helper, that helper is as dangerous as its
riskiest caller, whatever the docstring over `verify` says.

So it is enforced underneath:

```python
adapter = GithubAdapter.read_only()      # cannot change anything
```

A read-only transport refuses POST, PUT, PATCH and DELETE. An adapter may
share as much code as it likes and still cannot mutate, because the object it
was handed will not carry the request. That turns "safe to point at my own
account" from a claim about adapter discipline into a property of the object.

Some genuine verification endpoints are POST - OAuth introspection, for one -
so there is an escape hatch that demands a written reason. An exception you
have to write a sentence for is one somebody reads later; one you can take by
passing `True` is one that spreads.

The contract asserts every adapter's `verify` completes read-only, and there is
an adapter in the suite that mutates while verifying, with a test that the
contract catches it.

Two rules make that safe, structurally rather than by discipline:

- **Injection can only make the system more cautious.** You cannot hand it a
  response; you choose a shape, and no shape produces a success. Forging a
  working credential is not an API this module offers.
- **Nothing injected can become evidence.** `Vault.verify` refuses to run while
  injection is armed, because a rotation record is a claim about a real
  account.

Every injection site is one call, so one grep finds them all:

```
grep -n 'inject("' vaultline.py
```

and `vaultline.injection_points()` reports them with line numbers, parsed from
the source with `ast` so it cannot drift. Three tests prove the declared table
and the call sites match in both directions, and that **every declared point is
armed by at least one test** - a point no test exercises is a lie, because it
advertises a failure mode as considered when nothing has checked it.

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

**Pre-alpha.** Implemented and covered by 138 tests: the envelope, wrappings,
saving, location safety, the rotation state machine, the clipboard tier, and
the transport with its fault injection and adapter contract. Not implemented:
any real adapter, threshold recovery, and any command-line interface.

Nothing is published to PyPI yet.

## Running the tests

```
python vaultline_dev.py             # 138 tests
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
