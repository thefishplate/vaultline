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

#: The payload is a document, not a bare mapping, so that rotation state lives
#: inside the encryption alongside the values it describes. Version 0 was a
#: bare {name: value} mapping and is still read; it upgrades on the next save.
PAYLOAD_VERSION = 1

#: Rotation states. The one that matters is UNKNOWN.
#:
#: A service can accept a change and lose the response. Treating that as
#: failure - discarding the new value and keeping the old - is how an account
#: becomes unreachable, because the old value is the one that no longer works.
#: So UNKNOWN keeps *both* values and is resolved by asking the service, never
#: by assuming. A superset beats an empty set.
NONE = "none"
PENDING = "pending"
UNKNOWN = "unknown"
ACCEPTED = "accepted"
LOCKED_OUT = "locked_out"
ROTATION_STATES = (NONE, PENDING, UNKNOWN, ACCEPTED, LOCKED_OUT)

#: Attempting a wrong credential can lock an account. The limit is part of
#: correctness, not politeness: a verification that triggers lockout has
#: destroyed access while checking whether access works.
DEFAULT_MAX_ATTEMPTS = 3


class VaultlineError(Exception):
    """Base for every error this module raises deliberately."""


class BadPassphrase(VaultlineError):
    pass


class BadEnvelope(VaultlineError):
    pass


class UnsafeLocation(VaultlineError):
    pass


class RotationError(VaultlineError):
    pass


class LockedOut(RotationError):
    """Neither value authenticates. Nothing is deleted; a human must intervene."""


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


#: Where to look for gpg when it is not on PATH.
#:
#: On Windows this matters more than it should. GPG ships with Git, but Git
#: adds its bin directory to PATH only inside Git Bash - so the tool works in
#: one shell and fails in the one most people actually use, with an error that
#: says only "the system cannot find the file specified". These are product
#: install locations rather than machine-specific paths, and they are tried
#: after PATH, never instead of it.
GPG_FALLBACKS = (
    r"C:\Program Files\Git\usr\bin\gpg.exe",
    r"C:\Program Files (x86)\Git\usr\bin\gpg.exe",
    r"C:\Program Files\GnuPG\bin\gpg.exe",
    r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
)


def gpg_path():
    """Locate the gpg binary, or say clearly what to do about it.

    Order: an explicit override, then PATH, then known install locations. The
    override exists so a machine with an unusual layout has an answer that
    does not involve editing this file.
    """
    import os
    import pathlib as _pathlib
    import shutil

    override = os.environ.get("VAULTLINE_GPG")
    if override:
        if not _pathlib.Path(override).exists():
            raise VaultlineError(
                "VAULTLINE_GPG is set to %r, which does not exist" % override)
        return override
    found = shutil.which("gpg")
    if found:
        return found
    for candidate in GPG_FALLBACKS:
        if _pathlib.Path(candidate).exists():
            return candidate
    raise VaultlineError(
        "gpg was not found on PATH.\n"
        "  It ships with Git, but Git adds it to PATH only inside Git Bash,\n"
        "  so a PowerShell or cmd session will not see it.\n"
        "  Either add its directory to PATH, or set VAULTLINE_GPG to the full\n"
        "  path of gpg.exe - commonly inside the Git installation, under\n"
        "  usr/bin.")


def _gpg(args, data=None, passphrase=None):
    """Run gpg as a subprocess. It is never imported and never long-lived."""
    import subprocess

    argv = [gpg_path(), "--batch", "--yes", "--quiet"]
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


# ---------------------------------------------------------------------------
# Playbooks
#
# How to perform an operation at a site, expressed as data rather than code.
# A playbook cannot receive the vault, cannot make an arbitrary request, and
# cannot execute anything - it can only say things the interpreter already
# understands. That is the strongest form of the boundary this module keeps
# drawing, and it is what makes a shared or contributed playbook tenable.
#
# Two rules keep it declarative rather than becoming a bad programming
# language, which is where every automation format ends up:
#
#   No conditionals, no loops, no expressions, no waits, no retries. When a
#   site needs any of those it does not get a playbook - it drops to the tier
#   where a human does it. Timeouts and retries belong to the interpreter as
#   policy, so no playbook can express them.
#
# And two rules keep it safe:
#
#   **A playbook is procedure, never inventory.** It says how to change a
#   password at a site. It must not name an account, a username, or anything
#   about which accounts exist - that belongs in the encrypted payload. This is
#   what lets playbooks be shared while the vault stays private.
#
#   **A playbook does not choose where a secret goes.** The origin comes from
#   the credential record, and planning refuses any playbook whose URL leaves
#   it. A hostile playbook can waste your time; it cannot exfiltrate.
#
# Deciding is separated from doing. plan() is pure: it returns steps, contains
# no secret values, and is therefore safe to print. An executor resolves the
# roles to values at the last moment.
# ---------------------------------------------------------------------------


class PlaybookError(VaultlineError):
    """A playbook is malformed, or cannot be applied to this credential."""


#: Bumped when the playbook schema changes. A playbook declares the version it
#: was written for, and an interpreter meeting a newer one refuses.
PLAYBOOK_VERSION = 0

PLAYBOOK_OPERATIONS = ("change_password", "rotate_token", "revoke_token")

#: What a field in a form is for. Closed: an unrecognised role is an error,
#: never something to skip past.
FIELD_ROLES = ("current", "new", "confirm", "totp")

#: Where a filled value comes from. Note there is no "literal" - a playbook
#: cannot supply a value, only say which of the vault's values goes where.
FIELD_SOURCES = {"current": "current_value", "new": "candidate",
                 "confirm": "candidate", "totp": "totp"}

PLAYBOOK_KEYS = frozenset({
    "schema_version", "site", "operation", "sanction", "url", "fields",
    "submit", "challenges", "notes", "last_verified",
})

#: Keys that would turn a playbook into inventory. Named explicitly so the
#: refusal has a reason attached rather than being a mysterious rejection.
INVENTORY_KEYS = frozenset({
    "username", "user", "email", "account", "login", "password", "secret",
    "value", "token", "credential",
})


def validate_playbook(raw):
    """Check a playbook, or say exactly what is wrong with it.

    Unknown keys are an **error**, not something to ignore. An interpreter
    that shrugs at a key it does not understand will silently drop a
    constraint written by a later version - and a playbook that is quietly
    less safe than it claims is worse than one that refuses to load.
    """
    if not isinstance(raw, dict):
        raise PlaybookError("a playbook must be an object")

    version = raw.get("schema_version")
    if version is None:
        raise PlaybookError("playbook has no schema_version")
    if not isinstance(version, int) or version > PLAYBOOK_VERSION:
        raise PlaybookError(
            "playbook is schema version %r; this understands up to %d and "
            "will not guess" % (version, PLAYBOOK_VERSION))

    unknown = set(raw) - PLAYBOOK_KEYS
    if unknown:
        inventory = unknown & INVENTORY_KEYS
        if inventory:
            raise PlaybookError(
                "playbook carries %s, which is inventory rather than "
                "procedure. Accounts live in the vault; a playbook says only "
                "how to act at a site." % ", ".join(sorted(inventory)))
        raise PlaybookError("playbook has unknown keys: %s"
                            % ", ".join(sorted(unknown)))

    for required in ("site", "operation", "url", "fields"):
        if not raw.get(required):
            raise PlaybookError("playbook has no %s" % required)

    if raw["operation"] not in PLAYBOOK_OPERATIONS:
        raise PlaybookError("unknown operation %r; known: %s"
                            % (raw["operation"], ", ".join(PLAYBOOK_OPERATIONS)))
    if raw.get("sanction") not in ("documented", "incidental", "unsanctioned"):
        raise PlaybookError("playbook must declare a sanction")
    if not str(raw["url"]).startswith("https://"):
        raise PlaybookError("playbook url must be https")

    fields = raw["fields"]
    if not isinstance(fields, dict):
        raise PlaybookError("fields must be an object")
    for role, locator in fields.items():
        if role not in FIELD_ROLES:
            raise PlaybookError("unknown field role %r; known: %s"
                                % (role, ", ".join(FIELD_ROLES)))
        _validate_locator(role, locator)
    if raw.get("submit") is not None:
        _validate_locator("submit", raw["submit"])
    for name, locator in (raw.get("challenges") or {}).items():
        if name not in ("totp",):
            raise PlaybookError(
                "challenge %r cannot be answered by a playbook. Email and SMS "
                "codes need a human, so the plan hands over instead." % name)
        _validate_locator(name, locator)
    return raw


def _validate_locator(where, locator):
    if not isinstance(locator, dict) or not locator:
        raise PlaybookError("%s needs a locator object" % where)
    unknown = set(locator) - {"autocomplete", "selector", "index"}
    if unknown:
        raise PlaybookError("%s locator has unknown keys: %s"
                            % (where, ", ".join(sorted(unknown))))
    if not (locator.get("autocomplete") or locator.get("selector")):
        raise PlaybookError(
            "%s locator must give an autocomplete token or a selector. The "
            "autocomplete token is preferred: it is what the site itself "
            "declares, so it does not rot when the markup is restyled." % where)


def origin_of(url):
    """scheme://host[:port] - what a secret may not be sent outside of."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise PlaybookError("cannot read an origin from %r" % url)
    return "%s://%s" % (parts.scheme, parts.netloc)


def plan(playbook, credential, candidate=None):
    """Turn a playbook plus a credential record into steps.

    Pure: no network, no browser, no vault. The returned steps name *roles*
    rather than carrying values, so a plan can be printed, logged or shown to
    the operator without disclosing anything. The executor resolves roles at
    the last moment.

    `credential` is the vault's record: at least `origin`, and whatever the
    playbook's fields require.
    """
    playbook = validate_playbook(playbook)

    wanted = origin_of(playbook["url"])
    held = credential.get("origin")
    if not held:
        raise PlaybookError(
            "the credential record has no origin, so there is nothing to check "
            "the playbook against. Refusing rather than trusting the playbook.")
    if origin_of(held) != wanted:
        raise PlaybookError(
            "playbook would act at %s but the credential belongs to %s. A "
            "playbook does not choose where a secret goes." % (wanted, origin_of(held)))

    steps = [{"step": "open", "url": playbook["url"]}]
    for role in FIELD_ROLES:
        locator = playbook["fields"].get(role)
        if locator is None:
            continue
        source = FIELD_SOURCES[role]
        if source == "candidate" and candidate is None:
            raise PlaybookError(
                "%s needs a candidate value and none was generated" % role)
        if source == "current_value" and not credential.get("has_current"):
            raise PlaybookError(
                "%s needs the current value and the record does not have one" % role)
        steps.append({"step": "fill", "role": role, "source": source,
                      "locator": locator})

    for name, locator in sorted((playbook.get("challenges") or {}).items()):
        if name == "totp" and not credential.get("has_totp"):
            steps.append({"step": "handoff",
                          "reason": "the site may ask for a one-time code and "
                                    "this credential has no TOTP seed"})
            continue
        steps.append({"step": "fill", "role": name, "source": name,
                      "locator": locator, "optional": True})

    if playbook.get("submit"):
        steps.append({"step": "submit", "locator": playbook["submit"]})
    else:
        steps.append({"step": "handoff", "reason": "no submit control declared"})
    return steps


def plan_mentions_no_secrets(steps, *values):
    """True when no step carries any of *values*. Used by tests and callers
    that want to log a plan."""
    import json as _json

    blob = _json.dumps(steps)
    return not any(v and v in blob for v in values)


# ---------------------------------------------------------------------------
# Transport, and fault injection
#
# Adapters talk to services through Transport. The injection points live in
# this module permanently rather than in a test harness, because a hook that
# exists only under test cannot be exercised against the real world - and the
# failure handling you can never exercise in production is the failure handling
# you do not have.
#
# Two rules make that safe, and both are structural rather than a matter of
# discipline:
#
# 1. **Injection can only ever make the system more cautious.** You cannot hand
#    it a response; you choose a shape from FAILURE_SHAPES, and no shape in
#    that table produces a success. Forging a working credential is not an API
#    this module offers.
#
# 2. **Nothing injected may be read as evidence.** Vault.verify refuses to run
#    while injection is armed, because a rotation record is a claim about a
#    real account.
#
# Every injection site is a call to inject(), so one grep finds them all:
#
#     grep -n 'inject("' vaultline.py
#
# and injection_points() reports them with line numbers, so nobody has to know
# the incantation. Three tests prove the table and the call sites match, in
# both directions, and that every point is exercised.
# ---------------------------------------------------------------------------


class TransportError(VaultlineError):
    """The request did not complete. Not evidence about a credential."""


class AdapterError(VaultlineError):
    """An adapter met something it does not understand, and stopped."""


class ReadOnlyViolation(VaultlineError):
    """Something tried to change the world through a read-only transport."""


#: Every fault-injection point in this module, and the real failure each one
#: stands for. The table is the inventory; tests prove it matches the code.
INJECTION_POINTS = {
    "transport.request": "the outbound HTTP call an adapter makes",
}


#: The ways a service can fail, or change under us. Each names an `allowed`
#: set: what an adapter may conclude when it meets this shape.
#:
#: **True is in none of them.** That is the guarantee - injection cannot
#: manufacture a success, so an armed hook can make the tool refuse to decide
#: but never make it decide wrongly.
#:
#: `unauthorised` is the one case where False is permitted, because a 401 from
#: the endpoint you expected really is the service rejecting the credential.
#: It is also what a changed auth scheme looks like, and an adapter that cannot
#: tell those apart should return None - hence both are allowed.
FAILURE_SHAPES = {
    "gone": {
        "status": 404, "body": b'{"message":"Not Found"}',
        "means": "the endpoint moved or was withdrawn",
        "allowed": (None,)},
    "unauthorised": {
        "status": 401, "body": b'{"message":"Bad credentials"}',
        "means": "credential rejected, or the auth scheme changed",
        "allowed": (False, None)},
    "forbidden": {
        "status": 403, "body": b'{"message":"Forbidden"}',
        "means": "scope or permission narrowed",
        "allowed": (None,)},
    "rate_limited": {
        "status": 429, "body": b'{"message":"API rate limit exceeded"}',
        "means": "throttled - says nothing at all about the credential",
        "allowed": (None,)},
    "bad_request": {
        "status": 400, "body": b'{"message":"Missing required parameter"}',
        "means": "a new required parameter appeared",
        "allowed": (None,)},
    "server_error": {
        "status": 500, "body": b"upstream exploded",
        "means": "the service is unwell",
        "allowed": (None,)},
    "html_login": {
        "status": 200, "body": b"<html><body>Please sign in</body></html>",
        "means": "redirected to a login or consent page; HTML where JSON was",
        "allowed": (None,)},
    "renamed_field": {
        "status": 200, "body": b'{"account_name":"someone"}',
        "means": "200, but the field we read has been renamed",
        "allowed": (None,)},
    "empty_body": {
        "status": 200, "body": b"",
        "means": "200 with nothing in it",
        "allowed": (None,)},
    "truncated_json": {
        "status": 200, "body": b'{"login": "some',
        "means": "a partial read",
        "allowed": (None,)},
    "deprecated": {
        "status": 200, "body": b'{"login":"someone"}',
        "headers": {"Sunset": "Sat, 01 Nov 2026 00:00:00 GMT"},
        "means": "still working, and announcing that it will not be",
        "allowed": (True, None)},
    "timeout": {
        "raises": "timed out",
        "means": "connection lost mid-request",
        "allowed": (None,)},
    "connection_reset": {
        "raises": "connection reset by peer",
        "means": "the connection died",
        "allowed": (None,)},
}


class Response:
    """An HTTP response. Any status is data; only network failure raises."""

    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self.body = body
        self.headers = dict(headers or {})

    def json(self):
        """Parsed body, or None if it is not JSON. Never raises.

        An adapter that cannot parse the body has learned that the shape
        changed, which is a reason to decline rather than to crash.
        """
        import json as _json

        try:
            return _json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def __repr__(self):
        return "Response(%r, %d bytes)" % (self.status, len(self.body))


#: Armed injection: (point, shape) or None. Module state, deliberately, so
#: that it is visible to injection_active() and to the guard in Vault.verify.
_ARMED = {}


def arm(point, shape):
    """Arm a failure at an injection point. Returns a token for disarming.

    Deliberately available outside tests. Being able to inject a 429 against
    the real service, on purpose, and watch what happens is worth more than any
    fake - and it is safe here because no shape can produce a success.
    """
    if point not in INJECTION_POINTS:
        raise VaultlineError("unknown injection point %r; known: %s"
                             % (point, ", ".join(sorted(INJECTION_POINTS))))
    if shape not in FAILURE_SHAPES:
        raise VaultlineError("unknown failure shape %r; known: %s"
                             % (shape, ", ".join(sorted(FAILURE_SHAPES))))
    _ARMED[point] = shape
    return point


def disarm(point=None):
    if point is None:
        _ARMED.clear()
    else:
        _ARMED.pop(point, None)


def injection_active():
    """What is currently armed. Empty when nothing is."""
    return dict(_ARMED)


def inject(point, produce):
    """Return the real result, or the armed failure instead.

    `produce` is a callable so the real work is skipped entirely when a failure
    is armed - an injected timeout should not also make the request.
    """
    shape = _ARMED.get(point)
    if shape is None:
        return produce()
    spec = FAILURE_SHAPES[shape]
    if "raises" in spec:
        raise TransportError("injected %s: %s" % (shape, spec["raises"]))
    return Response(spec["status"], spec.get("body", b""), spec.get("headers"))


def injection_points():
    """Every injection site: name, what it stands for, and where it is.

    Parsed from this module's own source, so it cannot drift from the code the
    way a hand-kept list does.
    """
    import ast
    import pathlib as _pathlib

    source = _pathlib.Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "inject" and node.args
                and isinstance(node.args[0], ast.Constant)):
            name = node.args[0].value
            found.append({"point": name,
                          "means": INJECTION_POINTS.get(name, "(undeclared)"),
                          "line": node.lineno})
    return sorted(found, key=lambda f: f["line"])


#: Methods that may change something. HEAD and GET are absent, and OPTIONS
#: with them, because none of them is supposed to alter state.
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class Transport:
    """The only way an adapter reaches the network.

    One place for timeouts, one place for injection, and one place to look when
    asking what this program can talk to.

    **`readonly=True` is how rehearsing against a real account becomes
    defensible rather than merely careful.** Risk attaches to operations, but
    code is organised by path - and once `verify` and `submit` share a helper,
    that helper is as dangerous as its riskiest caller, whatever the docstring
    over `verify` says. Enforcing here means an adapter may share as much code
    as it likes and still cannot change anything, because the object it was
    handed will not carry the request.

    That turns "safe to point at my own account" from a claim about adapter
    discipline into a property of the object, which is the difference between
    a promise and a guarantee.
    """

    def __init__(self, timeout=10, readonly=False):
        self.timeout = timeout
        self.readonly = readonly

    def request(self, method, url, headers=None, body=None,
                side_effect_free=False, reason=None):
        """Make a request. Refuses to mutate when read-only.

        Some genuine verification endpoints are POST - OAuth token
        introspection, for one - so there is an escape hatch, and it demands a
        `reason` in the source. An exception you have to write a sentence for
        is an exception somebody reads later; one you can take by passing True
        is one that spreads.
        """
        if self.readonly and method.upper() in MUTATING_METHODS:
            if not side_effect_free:
                raise ReadOnlyViolation(
                    "%s %s through a read-only transport. If this really "
                    "changes nothing, pass side_effect_free=True with a reason."
                    % (method.upper(), url))
            if not reason:
                raise ReadOnlyViolation(
                    "%s %s claims to be side-effect-free but gives no reason. "
                    "Say why, in the source, so the next reader can check."
                    % (method.upper(), url))
        return inject("transport.request",
                      lambda: self._request(method, url, headers, body))

    def _request(self, method, url, headers, body):
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, data=body, method=method,
                                     headers=dict(headers or {}))
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return Response(r.status, r.read(), dict(r.headers))
        except urllib.error.HTTPError as exc:
            # A status code is data, not an exception. Adapters decide.
            return Response(exc.code, exc.read(), dict(exc.headers or {}))
        except Exception as exc:
            raise TransportError("%s %s: %s" % (method, url, exc)) from None


class Adapter:
    """What a service adapter must be.

    **An adapter never receives the Vault.** It is handed a value and returns a
    fact. A bad or compromised adapter should be able to lie about one
    credential, not hold the store.

    **It reports; the vault concludes.** `verify` returns True, False, or None
    for *could not tell*, and None is the right answer far more often than it
    looks. A 429 says nothing about a credential. Neither does a 500.

    **It fails closed.** Anything unrecognised raises AdapterError rather than
    being guessed at.
    """

    #: Whether this adapter uses an interface the service published, or drives
    #: something it was not invited to automate. Checked by CI: nothing
    #: unsanctioned belongs in this repository.
    sanction = None
    name = None
    version = None

    def __init__(self, transport=None):
        self.transport = transport or Transport()

    @classmethod
    def read_only(cls, timeout=10):
        """An adapter that cannot change anything, whatever its code does."""
        return cls(transport=Transport(timeout=timeout, readonly=True))

    def verify(self, value):
        raise NotImplementedError

    def __repr__(self):
        return "%s(%r, sanction=%r)" % (type(self).__name__, self.name,
                                        self.sanction)


# ---------------------------------------------------------------------------
# The clipboard tier
#
# The lowest-risk way to put a credential into a login form: the tool holds the
# value, you paste it. No browser is driven, no form is filled, nothing is
# automated that a service could object to - and it removes the part that
# actually hurts, which is finding and retyping a long random string.
#
# **The clear is a courtesy, not a control.** Any process running as you can
# read the clipboard at any moment, and on Windows the clipboard can be kept in
# a history and synced between devices. See clipboard_history_enabled().
# ---------------------------------------------------------------------------


def _clipboard_tools():
    """(write_argv, read_argv, clear_argv) for this platform, or None."""
    import shutil
    import sys as _sys

    if _sys.platform == "win32":
        ps = shutil.which("powershell") or shutil.which("pwsh")
        clip = shutil.which("clip")
        if ps:
            return (
                [ps, "-NoProfile", "-Command", "$input | Set-Clipboard"],
                [ps, "-NoProfile", "-Command", "Get-Clipboard -Raw"],
                # Set-Clipboard rejects an empty string, so clearing goes
                # through clip.exe, which accepts empty input happily.
                [clip] if clip else [ps, "-NoProfile", "-Command",
                                     "Set-Clipboard -Value ' '"],
            )
        return None
    if _sys.platform == "darwin":
        if shutil.which("pbcopy") and shutil.which("pbpaste"):
            return (["pbcopy"], ["pbpaste"], ["pbcopy"])
        return None
    for write, read in (("wl-copy", "wl-paste"), ("xclip", "xclip"), ("xsel", "xsel")):
        if shutil.which(write) and shutil.which(read):
            if write == "xclip":
                return (["xclip", "-selection", "clipboard"],
                        ["xclip", "-selection", "clipboard", "-o"],
                        ["xclip", "-selection", "clipboard"])
            if write == "xsel":
                return (["xsel", "--clipboard", "--input"],
                        ["xsel", "--clipboard", "--output"],
                        ["xsel", "--clipboard", "--input"])
            return (["wl-copy"], ["wl-paste", "-n"], ["wl-copy"])
    return None


def clipboard_available():
    return _clipboard_tools() is not None


def clipboard_write(value):
    import subprocess

    tools = _clipboard_tools()
    if tools is None:
        raise VaultlineError(
            "no clipboard tool found. On Linux install xclip, xsel or wl-clipboard.")
    r = subprocess.run(tools[0], input=value.encode("utf-8"), capture_output=True)
    if r.returncode != 0:
        raise VaultlineError("could not write to the clipboard: %s"
                             % r.stderr.decode("utf-8", "replace").strip()[:200])


def clipboard_read():
    """Current clipboard text, or None if it cannot be read."""
    import subprocess

    tools = _clipboard_tools()
    if tools is None:
        return None
    r = subprocess.run(tools[1], capture_output=True)
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", "replace").rstrip("\r\n")


def clipboard_clear(only_if=None):
    """Empty the clipboard, optionally only when it still holds *only_if*.

    The guard matters. Between putting a password on the clipboard and clearing
    it, the operator has very likely copied something else - and wiping their
    work to tidy up after ourselves would be its own small betrayal.
    """
    import subprocess

    tools = _clipboard_tools()
    if tools is None:
        return False
    if only_if is not None:
        current = clipboard_read()
        if current is not None and current != only_if:
            return False
    subprocess.run(tools[2], input=b"", capture_output=True)
    return True


def clipboard_history_enabled():
    """Whether Windows is keeping a clipboard history. None if not knowable.

    This is the single most important thing to know before trusting a timed
    clear. With history on, the value stays in Win+V after the clipboard is
    emptied, and with cloud sync on it has already left the machine. The clear
    then removes nothing that mattered.

    Absent registry values mean the feature is off - it is opt-in.
    """
    import sys as _sys

    if _sys.platform != "win32":
        return False
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Clipboard") as key:
            history = _reg_dword(winreg, key, "EnableClipboardHistory")
            cloud = _reg_dword(winreg, key, "CloudClipboardAutomaticUpload")
            return bool(history) or bool(cloud)
    except OSError:
        return False
    except ImportError:  # pragma: no cover - not Windows
        return None


def _reg_dword(winreg, key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return 0


class Vault:
    """One vault file: a plaintext envelope around encrypted blobs.

    Construct with `create()` or `open()`. Neither holds a passphrase after it
    returns - the master key is held for the life of the object, and callers
    that care should not keep one alive longer than they need to.
    """

    def __init__(self, path, envelope, master_key, secrets, payload=None,
                 rotations=None):
        self.path = path
        self.envelope = envelope
        self._master = master_key
        self.secrets = secrets
        self.rotations = dict(rotations or {})
        # The payload ciphertext as it currently stands on disk, and a snapshot
        # of what it decrypts to. Together they let save() tell whether the
        # contents actually changed - see the note there.
        self._payload = payload
        self._clean = self._document_json()

    def _document(self):
        """The decrypted payload, as it is written."""
        return {
            "payload_version": PAYLOAD_VERSION,
            "secrets": self.secrets,
            "rotations": self.rotations,
        }

    def _document_json(self):
        import json

        return json.dumps(self._document(), indent=2, sort_keys=True)

    @staticmethod
    def _parse_document(raw):
        """Read a payload document, accepting the version 0 bare mapping.

        Returns (secrets, rotations). A version this reader does not know is
        refused rather than partially understood: silently ignoring a field it
        cannot interpret is how a half-finished rotation gets lost.
        """
        if not isinstance(raw, dict):
            raise BadEnvelope("payload is not an object")
        if "payload_version" not in raw:
            return dict(raw), {}          # version 0: a bare mapping
        version = raw.get("payload_version")
        if not isinstance(version, int) or version > PAYLOAD_VERSION:
            raise BadEnvelope(
                "payload is version %r; this reader understands up to %d and "
                "will not guess" % (version, PAYLOAD_VERSION))
        return dict(raw.get("secrets") or {}), dict(raw.get("rotations") or {})

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
        if payload:
            secrets, rotations = cls._parse_document(
                json.loads(_decrypt(payload, master).decode("utf-8")))
        else:
            secrets, rotations = {}, {}
        return cls(path, envelope, master, secrets, payload=payload,
                   rotations=rotations)

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
        document = self._document_json()
        if self._payload is not None and document == self._clean:
            envelope["payload"] = self._payload
        else:
            envelope["payload"] = _encrypt(document.encode("utf-8"), self._master)

        tmp = self.path.parent / (self.path.name + ".new")
        tmp.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

        check = json.loads(tmp.read_text(encoding="utf-8"))
        self._check_envelope(check)
        back_secrets, back_rotations = self._parse_document(
            json.loads(_decrypt(check["payload"], self._master).decode("utf-8")))
        if back_secrets != self.secrets or back_rotations != self.rotations:
            tmp.unlink(missing_ok=True)
            raise VaultlineError(
                "ABORT - the file read back with %d secrets and %d rotations, "
                "expected %d and %d. %s is untouched."
                % (len(back_secrets), len(back_rotations), len(self.secrets),
                   len(self.rotations), self.path.name))

        backup = None
        if self.path.exists():
            backup = self.path.parent / (self.path.name + ".bak")
            backup.write_bytes(self.path.read_bytes())
        tmp.replace(self.path)
        self.envelope = envelope
        self._payload = envelope["payload"]
        self._clean = document
        return backup

    # -- rotation --------------------------------------------------------
    #
    # The failure this exists to prevent: a service accepts a new value, the
    # record of it is lost, and the account becomes unreachable. Every rule
    # below follows from that one sentence.

    def rotation(self, name):
        """The rotation record for a secret, or a fresh one."""
        return self.rotations.get(name) or {"state": NONE, "attempts": 0}

    def rotation_state(self, name):
        return self.rotation(name)["state"]

    def pending(self, name):
        """The candidate value, if one exists. What the operator types in."""
        return self.rotation(name).get("pending")

    def attempts_remaining(self, name):
        r = self.rotation(name)
        return max(0, r.get("max_attempts", DEFAULT_MAX_ATTEMPTS) - r.get("attempts", 0))

    def begin_rotation(self, name, new_value, at=None, max_attempts=None,
                       override_sync=False):
        """Record a candidate, and write it to disk **before** it is submitted.

        The ordering is the whole point. If the candidate is submitted first
        and the machine dies before the record is written, the only copy of a
        value the service may now be enforcing is gone. Writing first means a
        crash at any moment afterwards leaves both values on disk, and a
        superset is always recoverable where an empty set is not.

        This saves. It is not an in-memory operation that you remember to
        persist, because remembering is exactly what fails.
        """
        if not new_value:
            raise RotationError("a rotation needs a candidate value")
        state = self.rotation_state(name)
        if state in (PENDING, UNKNOWN, ACCEPTED):
            raise RotationError(
                "%s is already mid-rotation (%s); resolve it before starting another"
                % (name, state))
        self.rotations[name] = {
            "state": PENDING,
            "pending": new_value,
            "previous": self.secrets.get(name),
            "started_at": at,
            "attempts": 0,
            "max_attempts": max_attempts or DEFAULT_MAX_ATTEMPTS,
        }
        self.save(override_sync=override_sync)
        return self.rotations[name]

    def record_outcome(self, name, outcome, at=None, override_sync=False):
        """Classify what the service did with the submission.

        Three outcomes, and the middle one is the reason this is a state
        machine rather than an if-statement:

        - ``rejected``  - demonstrably refused *before* being applied: a
          validation error, a policy rejection. Only then is it safe to
          discard the candidate.
        - ``unknown``   - a timeout, a 5xx, a dropped connection, anything
          ambiguous. **Both values are kept.** Never deleted.
        - ``accepted``  - the form was taken. This is *not* activation: the
          service may have truncated or normalised what it stored, so the old
          value is retained until a fresh login proves which one is in force.
        """
        if outcome not in ("rejected", "unknown", "accepted"):
            raise RotationError("outcome must be rejected, unknown or accepted")
        r = self.rotations.get(name)
        if not r or r["state"] != PENDING:
            raise RotationError("%s has no submitted rotation to classify" % name)
        if outcome == "rejected":
            # The only branch that discards anything, and only because the
            # service said it never applied the change.
            del self.rotations[name]
        else:
            r["state"] = UNKNOWN if outcome == "unknown" else ACCEPTED
            r["classified_at"] = at
        self.save(override_sync=override_sync)
        return self.rotations.get(name)

    def verify(self, name, verifier, at=None, override_sync=False,
               allow_injected=False):
        """Decide which value is in force, by asking the service.

        `verifier(value)` returns True if that value authenticates, False if it
        demonstrably does not, and **None if it could not tell** - a network
        failure is not evidence either way, and treating it as one is the same
        mistake as treating an ambiguous submission as failure.

        The vault calls the verifier and draws the conclusion. The verifier
        supplies a fact, never a verdict: an adapter that could return
        "success" on its own authority could talk this into retiring a working
        credential.
        """
        r = self.rotations.get(name)
        if not r or r["state"] not in (UNKNOWN, ACCEPTED):
            raise RotationError("%s has no rotation awaiting verification" % name)
        if _ARMED and not allow_injected:
            # A rotation record is a claim about a real account. Nothing
            # produced by fault injection may become one.
            raise RotationError(
                "fault injection is armed (%s) and would be recorded as fact. "
                "Disarm, or pass allow_injected=True if this is a test."
                % ", ".join("%s=%s" % kv for kv in sorted(_ARMED.items())))
        if self.attempts_remaining(name) <= 0:
            raise RotationError(
                "%s has no attempts left (%d used). Trying again risks locking "
                "the account; use the recovery path instead."
                % (name, r.get("attempts", 0)))

        r["attempts"] = r.get("attempts", 0) + 1
        self.save(override_sync=override_sync)

        result = verifier(r["pending"])
        if result is None:
            return UNKNOWN                     # learned nothing; nothing changes
        if result:
            self.secrets[name] = r["pending"]  # the candidate is in force
            del self.rotations[name]
            self.save(override_sync=override_sync)
            return "active"

        if self.attempts_remaining(name) <= 0:
            raise RotationError(
                "%s: the candidate failed and there are no attempts left to "
                "test the previous value. Stopping rather than risking lockout."
                % name)
        r["attempts"] += 1
        self.save(override_sync=override_sync)
        previous = verifier(r.get("previous"))
        if previous:
            # The change did not take. Now, and only now, is the candidate junk.
            del self.rotations[name]
            self.save(override_sync=override_sync)
            return NONE
        if previous is None:
            return UNKNOWN

        r["state"] = LOCKED_OUT
        r["locked_out_at"] = at
        self.save(override_sync=override_sync)
        raise LockedOut(
            "%s: neither the candidate nor the previous value authenticates. "
            "Nothing has been deleted - both are still in the vault. Use the "
            "account recovery path." % name)

    def mid_rotation(self):
        """Every secret not currently in a settled state. The work list."""
        return {n: r for n, r in self.rotations.items() if r["state"] != NONE}

    # -- handing a value to the operator ---------------------------------

    def to_clipboard(self, name, seconds=30, announce=None, sleep=None,
                     now=None):
        """Put a secret on the clipboard, wait, then take it back.

        This **blocks** for the duration, and that is deliberate rather than
        lazy. A background timer does not survive the process exiting, so a
        one-liner that copied and returned would leave the value on the
        clipboard indefinitely while appearing to have cleaned up - the worst
        combination available. Blocking means the clear always happens, and
        Ctrl-C brings it forward rather than skipping it.

        The value is never printed, never returned, and never logged. What the
        caller gets back is what happened, not what was copied.
        """
        import time as _time

        if name not in self.secrets:
            raise VaultlineError("no secret called %r" % name)
        sleep = sleep or _time.sleep
        now = now or _time.monotonic
        announce = announce or (lambda text: print(text, end="", flush=True))

        value = self.secrets[name]
        clipboard_write(value)

        history = clipboard_history_enabled()
        if history:
            announce(
                "\n  WARNING: Windows clipboard history is on. Clearing the\n"
                "  clipboard will not remove this from Win+V, and if cloud\n"
                "  sync is on it has already left this machine.\n")

        announce("\n  %s is on the clipboard. Paste it now.\n" % name)
        deadline = now() + seconds
        interrupted = False
        try:
            while True:
                left = deadline - now()
                if left <= 0:
                    break
                announce("\r  clearing in %2ds   Ctrl-C to clear now " % int(left + 0.5))
                sleep(min(0.25, left))
        except KeyboardInterrupt:
            # KeyboardInterrupt is a BaseException, so an outer `except
            # Exception` would not catch it - and the clear must happen.
            interrupted = True

        cleared = clipboard_clear(only_if=value)
        announce("\r" + " " * 44 + "\r")
        if cleared:
            announce("  cleared.\n" if not interrupted else "  cleared early.\n")
        else:
            announce("  left alone - you copied something else since.\n")
        return {"name": name, "cleared": cleared, "interrupted": interrupted,
                "history_enabled": history}

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
