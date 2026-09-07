# Contributing

## Invariants

These are not style preferences. Each one is load-bearing.

**No third-party Python dependencies.** Standard library only. GPG is invoked
as a subprocess and never imported.

**GPG owns the container.** We define a payload schema inside it. Building a
container is how unauthenticated headers and homemade integrity checks happen.
If a change requires touching the container, raise it rather than making it.

**The payload key is random, never derived from a passphrase.** This is what
makes the ciphertext safe to replicate. A change that derives it from something
memorable removes the entire justification for the design.

**Adding or removing a wrapping must leave the payload byte-identical.**
Tested. GPG picks a fresh session key on every run, so re-encrypting
unconditionally looks harmless and quietly destroys the property.

**The envelope carries no inventory.** No names, no counts, no services. If a
field would help a finder decide what to attack, it belongs in the payload.

**The passphrase is stretched before GPG sees it**, because GPG's S2K is not
memory-hard. Parameters are recorded in the file, never assumed.

**Nothing executable at module level**, and no import that can fail at import
time. A module-level failure in a process without a console dies silently.

## Before changing the envelope schema

A published copy cannot be unpublished. Adding a field is usually safe; changing
the meaning of an existing one is not, because files already in the world carry
the old meaning and there is nobody left to re-ask. Bump `FORMAT_VERSION` and
make the reader refuse rather than guess.

## Pre-commit

1. `python -m py_compile vaultline.py vaultline_dev.py`
2. `python vaultline_dev.py`
3. New markdown files are gitignored by default - add an allowlist line to
   `.gitignore` if the document is meant to be tracked.
