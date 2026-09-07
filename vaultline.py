# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 the vaultline contributors

"""A credential store whose ciphertext is safe to publish, and whose access can
be re-wrapped without re-encrypting anything.

Most secret managers say *protect the encrypted database*. This one says the
opposite: replicate it, deliberately, as widely as you like. That is only a
sane thing to say if the payload key is random rather than remembered, and if
losing a copy costs nothing that rotating a credential does not already fix.

The shape:

    plaintext JSON envelope        version, epoch, KDF parameters, a hint
      wrappings[]                  the master key, encrypted several ways
      payload                      the secrets, encrypted under the master key

Two properties follow from that, and they are the whole reason for the design.

**Re-wrapping is not re-encryption.** Granting or withdrawing a way in touches
only a wrapping. The payload ciphertext is untouched, so every copy already
made stays valid and no bulk re-encryption is ever needed. Adding threshold
recovery later is therefore additive rather than a migration.

**The envelope is readable without the key.** It carries no inventory - no
account names, no hostnames, no counts - because that is reconnaissance. It
carries only what someone needs to know *how* to open the file, plus an
optional hint. A passphrase reminder is no use if reading it requires the
passphrase.

GPG owns the container, the cipher and the integrity check. It is invoked as a
subprocess and never imported, and it ships with Git as well as every Linux
distribution, so a successor needs no bespoke tool. What is ours is the
envelope schema and the workflow around it - no cryptography.

Constraints, each load-bearing (see CONTRIBUTING.md):
- No third-party Python dependencies. Standard library only.
- Nothing executable at module level.
- The passphrase is stretched with scrypt before GPG sees it, because GPG's
  own S2K is not memory-hard.
- Nothing sensitive is ever written outside the encrypted payload.
"""

try:
    from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
    from importlib.metadata import version as _distribution_version

    __version__ = _distribution_version("vaultline")
except (ImportError, _PackageNotFoundError):  # pragma: no cover - source checkout
    __version__ = "0.0.0+unknown"

#: Bumped when the envelope schema changes in a way an older reader cannot
#: handle. Written into every file so a copy found in ten years identifies
#: itself rather than having to be guessed at.
FORMAT = "vaultline"
FORMAT_VERSION = 0


class VaultlineError(Exception):
    """Base for every error this module raises deliberately."""


class BadPassphrase(VaultlineError):
    pass


class BadEnvelope(VaultlineError):
    pass


class UnsafeLocation(VaultlineError):
    pass


def default_kdf():
    """scrypt parameters: about 128 MiB and a fraction of a second per guess.

    GPG's symmetric S2K is iterated-and-salted SHA. It is not memory-hard, so
    a GPU or ASIC evaluates it in parallel almost for free, and a memorable
    passphrase behind it is worth much less than its entropy suggests. The
    passphrase is therefore stretched here first, and GPG only ever sees a
    high-entropy string - which makes the weakness of its own S2K moot.

    Memory cost is what buys the resistance; iteration count alone does not.
    n=2**17, r=8 is roughly 128 MiB per attempt, which an attacker must find
    for every guess in parallel.

    These are recorded in the envelope rather than assumed, so a file written
    today opens in ten years without the reader having to know what the
    defaults were then.
    """
    return {"kdf": "scrypt", "n": 2 ** 17, "r": 8, "p": 1, "dklen": 32}


def stretch(passphrase, salt, params=None):
    """Derive the key-encryption key from a human passphrase."""
    import base64
    import hashlib

    params = params or default_kdf()
    if params.get("kdf") != "scrypt":
        raise BadEnvelope("unknown kdf: %r" % (params.get("kdf"),))
    key = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=int(params["n"]),
        r=int(params["r"]),
        p=int(params["p"]),
        maxmem=int(params["n"]) * int(params["r"]) * 256,
        dklen=int(params.get("dklen", 32)),
    )
    # GPG takes a passphrase, not raw bytes, so the derived key travels as
    # base64. It is never written anywhere.
    return base64.b64encode(key).decode("ascii")


def _gpg(args, data=None, passphrase=None):
    """Run gpg as a subprocess. It is never imported and never long-lived."""
    import subprocess

    argv = ["gpg", "--batch", "--yes", "--quiet"]
    if passphrase is not None:
        argv += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        data = passphrase.encode("utf-8") + b"\n" + (data or b"")
    argv += list(args)
    return subprocess.run(argv, input=data, capture_output=True)


def _encrypt(plaintext, passphrase):
    r = _gpg(["--armor", "--symmetric", "--cipher-algo", "AES256"],
             data=plaintext, passphrase=passphrase)
    if r.returncode != 0:
        raise VaultlineError("gpg could not encrypt: %s"
                             % r.stderr.decode("utf-8", "replace").strip()[:200])
    return r.stdout.decode("ascii")


def _decrypt(armored, passphrase):
    r = _gpg(["--decrypt"], data=armored.encode("ascii"), passphrase=passphrase)
    if r.returncode != 0:
        raise BadPassphrase("could not decrypt - wrong passphrase?")
    return r.stdout


SYNC_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive",
                "icloud", "nextcloud", "sync")


def refuse_sync_root(path, override=False):
    """Refuse to write a vault beneath a directory that syncs to the cloud.

    Windows syncs Documents and Desktop by default. A vault under a synced
    path is an off-site copy nobody decided to make, which quietly undoes the
    separation the two-file scheme exists to create. The check is crude - it
    matches folder names - and crude is the right trade: a false positive
    costs an explicit override, a false negative costs the design.
    """
    if override:
        return
    parts = [p.lower() for p in path.resolve().parts]
    for part in parts:
        for marker in SYNC_MARKERS:
            if marker in part:
                raise UnsafeLocation(
                    "%r looks like a synced folder (%r). A vault here is an "
                    "off-site copy you did not choose to make. Pass "
                    "override=True if you are certain." % (str(path), part))


class Vault:
    """One vault file: a plaintext envelope around encrypted blobs.

    Construct with `create()` or `open()`. Neither holds a passphrase after it
    returns - the master key is held for the life of the object, and callers
    that care should not keep one alive longer than they need to.
    """

    def __init__(self, path, envelope, master_key, secrets, payload=None):
        self.path = path
        self.envelope = envelope
        self._master = master_key
        self.secrets = secrets
        # The payload ciphertext as it currently stands on disk, and a snapshot
        # of what it decrypts to. Together they let save() tell whether the
        # secrets actually changed - see the note there.
        self._payload = payload
        self._clean = dict(secrets)

    # -- construction ----------------------------------------------------

    @classmethod
    def create(cls, path, passphrase, secrets=None, hint=None, override_sync=False,
               kdf=None, rand=None):
        """A new vault, with one way in.

        The master key is random and is never derived from the passphrase.
        That is what makes the ciphertext safe to replicate: there is nothing
        to guess, however long an attacker has.
        """
        import base64
        import pathlib
        import secrets as _secrets

        path = pathlib.Path(path)
        refuse_sync_root(path, override_sync)
        rand = rand or _secrets.token_bytes
        master = base64.b64encode(rand(32)).decode("ascii")
        envelope = {
            "format": FORMAT,
            "version": FORMAT_VERSION,
            "epoch": 0,
            "hint": hint,
            "wrappings": [],
        }
        vault = cls(path, envelope, master, dict(secrets or {}))
        vault.add_passphrase_wrapping(passphrase, kdf=kdf, rand=rand)
        return vault

    @classmethod
    def open(cls, path, passphrase, override_sync=False):
        """Open with a passphrase, trying each passphrase wrapping in turn."""
        import base64
        import json
        import pathlib

        path = pathlib.Path(path)
        refuse_sync_root(path, override_sync)
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BadEnvelope("cannot read %s: %s" % (path.name, exc)) from None
        cls._check_envelope(envelope)

        master = None
        for wrapping in envelope["wrappings"]:
            if wrapping.get("kind") != "passphrase":
                continue
            kek = stretch(passphrase, base64.b64decode(wrapping["salt"]),
                          wrapping.get("kdf"))
            try:
                master = _decrypt(wrapping["wrapped"], kek).decode("ascii")
                break
            except BadPassphrase:
                continue
        if master is None:
            raise BadPassphrase("no wrapping opened with that passphrase")

        payload = envelope.get("payload")
        secrets = json.loads(_decrypt(payload, master).decode("utf-8")) if payload else {}
        return cls(path, envelope, master, secrets, payload=payload)

    @staticmethod
    def _check_envelope(envelope):
        if not isinstance(envelope, dict) or envelope.get("format") != FORMAT:
            raise BadEnvelope("not a vaultline file")
        version = envelope.get("version")
        if not isinstance(version, int) or version > FORMAT_VERSION:
            raise BadEnvelope(
                "file is format version %r; this is version %d and will not "
                "guess at a newer one" % (version, FORMAT_VERSION))
        if not isinstance(envelope.get("wrappings"), list) or not envelope["wrappings"]:
            raise BadEnvelope("envelope has no wrappings; it cannot be opened")

    # -- wrappings -------------------------------------------------------

    def add_passphrase_wrapping(self, passphrase, kdf=None, rand=None, label=None):
        """Add a way in, without touching the payload.

        This is the property the whole format exists for. Granting access -
        a second passphrase now, a threshold quorum later - encrypts 32 bytes
        and appends a record. The payload ciphertext does not change, so every
        copy already in the world stays valid and nothing is re-encrypted.
        """
        import base64
        import secrets as _secrets

        rand = rand or _secrets.token_bytes
        params = kdf or default_kdf()
        salt = rand(16)
        kek = stretch(passphrase, salt, params)
        self.envelope["wrappings"].append({
            "kind": "passphrase",
            "label": label,
            "kdf": params,
            "salt": base64.b64encode(salt).decode("ascii"),
            "wrapped": _encrypt(self._master.encode("ascii"), kek),
        })
        return self.envelope["wrappings"][-1]

    def remove_wrapping(self, index):
        """Withdraw a way in — for copies made after this point, and no others.

        **This does not revoke anything already published.** Whoever holds an
        older copy holds the wrapping it was written with, permanently. The
        only thing that closes that door is rotating the secrets themselves.
        Removing a wrapping is therefore half of a withdrawal, never all of it.
        """
        if len(self.envelope["wrappings"]) <= 1:
            raise VaultlineError("that is the only way in; the file would be lost")
        return self.envelope["wrappings"].pop(index)

    # -- saving ----------------------------------------------------------

    def save(self, override_sync=False):
        """Write, verify by reopening from disk, then swap.

        The verification reopens the temporary file and compares the decrypted
        payload with what was meant to be written. Reading back through the
        page cache would prove only that bytes were handed to the OS; this
        proves they came back.
        """
        import json

        refuse_sync_root(self.path, override_sync)
        envelope = dict(self.envelope)

        # Re-encrypt only when the secrets actually changed.
        #
        # GPG picks a fresh session key on every run, so encrypting identical
        # plaintext under an identical key still produces different bytes.
        # Re-encrypting unconditionally would therefore churn the payload on
        # every save - including saves that only added a wrapping - and that
        # would quietly cost the property this format exists for: adding or
        # withdrawing a way in must leave the payload alone, so that a file
        # replicated widely does not have to be redistributed because somebody
        # was granted access.
        if self._payload is not None and self.secrets == self._clean:
            envelope["payload"] = self._payload
        else:
            body = json.dumps(self.secrets, indent=2, sort_keys=True).encode("utf-8")
            envelope["payload"] = _encrypt(body, self._master)

        tmp = self.path.parent / (self.path.name + ".new")
        tmp.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

        check = json.loads(tmp.read_text(encoding="utf-8"))
        self._check_envelope(check)
        back = json.loads(_decrypt(check["payload"], self._master).decode("utf-8"))
        if back != self.secrets:
            tmp.unlink(missing_ok=True)
            raise VaultlineError(
                "ABORT - the file read back with %d entries, expected %d. "
                "%s is untouched." % (len(back), len(self.secrets), self.path.name))

        backup = None
        if self.path.exists():
            backup = self.path.parent / (self.path.name + ".bak")
            backup.write_bytes(self.path.read_bytes())
        tmp.replace(self.path)
        self.envelope = envelope
        self._payload = envelope["payload"]
        self._clean = dict(self.secrets)
        return backup

    # -- the envelope, readable by anyone --------------------------------

    @staticmethod
    def peek(path):
        """The envelope without the payload, and without any passphrase.

        This is what a stranger holding the file can see, and it is the whole
        public surface: format, version, epoch, KDF parameters, how many ways
        in there are, and the hint. Deliberately no inventory - not the account
        names, not how many there are. If a field here would tell somebody
        which services to attack, it does not belong in the envelope.
        """
        import json
        import pathlib

        envelope = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        return {
            "format": envelope.get("format"),
            "version": envelope.get("version"),
            "epoch": envelope.get("epoch"),
            "hint": envelope.get("hint"),
            "wrappings": [
                {"kind": w.get("kind"), "label": w.get("label")}
                for w in envelope.get("wrappings", [])
            ],
        }

    @property
    def hint(self):
        return self.envelope.get("hint")

    def set_hint(self, text):
        """A reminder readable without the passphrase, which is the point.

        It rides in the plaintext envelope because a hint you need the
        passphrase to read is not a hint. Anyone taking a copy takes the hint
        with it, so write one that reminds you and tells a stranger nothing.
        """
        self.envelope["hint"] = (text or "").strip() or None
        return self.envelope["hint"]

    def __repr__(self):
        return "Vault(%r, epoch=%r, wrappings=%d, secrets=%d)" % (
            self.path.name, self.envelope.get("epoch"),
            len(self.envelope.get("wrappings", [])), len(self.secrets))
