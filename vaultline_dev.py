# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 the vaultline contributors
"""Development tooling for vaultline: the test suite.

Nothing here is imported by the library. It is not shipped in the wheel.

    python vaultline_dev.py                run the test suite (default)
    python vaultline_dev.py test           same, explicitly
    python vaultline_dev.py test -v        verbose
    python vaultline_dev.py test --fast    skip the slow real-KDF cases

Also runnable through the standard entry points, since the TestCase classes
live at module level:

    python -m unittest vaultline_dev
    python -m unittest vaultline_dev.RewrapTests

Standard library only, plus the gpg binary — which ships with Git, so a
machine that can clone this can run it.

**The suite uses deliberately weak KDF parameters.** Real ones cost about
128 MiB and a fraction of a second per call, and the suite makes hundreds of
calls. `WEAK_KDF` keeps it quick; `KdfTests` exercises the real parameters
once, because a suite that only ever tests the cheap path is not testing the
thing that ships.
"""

import argparse
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

import vaultline

#: n=2**10 is about 1 MiB. Nowhere near enough for real use, and the point of
#: the KDF being recorded in the envelope is that this is a parameter and not
#: a constant.
WEAK_KDF = {"kdf": "scrypt", "n": 2 ** 10, "r": 8, "p": 1, "dklen": 32}

PASS = "correct horse battery staple"
OTHER = "ten words that live on paper in two places"


def gpg_available():
    import subprocess

    try:
        return subprocess.run(["gpg", "--version"], capture_output=True).returncode == 0
    except OSError:
        return False


class VaultCase(unittest.TestCase):
    """Base: a temporary directory and a helper that builds a vault in it."""

    def setUp(self):
        if not gpg_available():
            self.skipTest("gpg is not on PATH")
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="vaultline-test-"))
        self.path = self.dir / "test.vaultline"

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def make(self, secrets=None, hint=None, passphrase=PASS):
        v = vaultline.Vault.create(self.path, passphrase, kdf=WEAK_KDF,
                                   secrets=secrets or {"GITHUB": "hunter2"},
                                   hint=hint)
        v.save()
        return v

    def payload(self):
        return json.loads(self.path.read_text(encoding="utf-8"))["payload"]


class RoundTripTests(VaultCase):
    def test_create_save_open(self):
        self.make(secrets={"A": "1", "B": "2"})
        v = vaultline.Vault.open(self.path, PASS)
        self.assertEqual(v.secrets, {"A": "1", "B": "2"})

    def test_wrong_passphrase_is_refused(self):
        self.make()
        with self.assertRaises(vaultline.BadPassphrase):
            vaultline.Vault.open(self.path, "not it")

    def test_an_empty_vault_round_trips(self):
        v = vaultline.Vault.create(self.path, PASS, kdf=WEAK_KDF, secrets={})
        v.save()
        self.assertEqual(vaultline.Vault.open(self.path, PASS).secrets, {})

    def test_values_are_not_in_the_file_in_clear(self):
        self.make(secrets={"GITHUB": "a-very-distinctive-value"})
        self.assertNotIn("a-very-distinctive-value",
                         self.path.read_text(encoding="utf-8"))

    def test_key_names_are_not_in_the_file_in_clear(self):
        # The inventory is the reconnaissance, not just the values.
        self.make(secrets={"REGISTRAR_FOR_THE_DOMAIN": "x"})
        self.assertNotIn("REGISTRAR_FOR_THE_DOMAIN",
                         self.path.read_text(encoding="utf-8"))


class RewrapTests(VaultCase):
    """The property the format exists for. A failure here is the whole design."""

    def test_adding_a_wrapping_leaves_the_payload_byte_identical(self):
        self.make()
        before = self.payload()
        v = vaultline.Vault.open(self.path, PASS)
        v.add_passphrase_wrapping(OTHER, kdf=WEAK_KDF, label="archive")
        v.save()
        self.assertEqual(before, self.payload())

    def test_both_passphrases_open_the_same_secrets(self):
        self.make(secrets={"A": "1"})
        v = vaultline.Vault.open(self.path, PASS)
        v.add_passphrase_wrapping(OTHER, kdf=WEAK_KDF)
        v.save()
        self.assertEqual(vaultline.Vault.open(self.path, PASS).secrets, {"A": "1"})
        self.assertEqual(vaultline.Vault.open(self.path, OTHER).secrets, {"A": "1"})

    def test_changing_a_secret_does_re_encrypt(self):
        # The converse. If this passed too, the dirty check would be broken
        # in the direction that loses data rather than the one that churns.
        self.make()
        before = self.payload()
        v = vaultline.Vault.open(self.path, PASS)
        v.secrets["NEW"] = "value"
        v.save()
        self.assertNotEqual(before, self.payload())
        self.assertEqual(vaultline.Vault.open(self.path, PASS).secrets["NEW"], "value")

    def test_removing_a_wrapping_leaves_the_payload_alone(self):
        self.make()
        v = vaultline.Vault.open(self.path, PASS)
        v.add_passphrase_wrapping(OTHER, kdf=WEAK_KDF)
        v.save()
        before = self.payload()
        v.remove_wrapping(1)
        v.save()
        self.assertEqual(before, self.payload())
        with self.assertRaises(vaultline.BadPassphrase):
            vaultline.Vault.open(self.path, OTHER)

    def test_the_last_wrapping_cannot_be_removed(self):
        # Removing it would leave a file nobody can ever open.
        self.make()
        v = vaultline.Vault.open(self.path, PASS)
        with self.assertRaises(vaultline.VaultlineError):
            v.remove_wrapping(0)

    def test_an_older_copy_still_opens_after_a_wrapping_is_removed(self):
        """Removal is half a withdrawal, and the docstring says so.

        Whoever holds an earlier copy holds the wrapping it was written with,
        permanently. Only rotating the secret closes that door. This test
        exists so nobody later mistakes removal for revocation.
        """
        self.make()
        v = vaultline.Vault.open(self.path, PASS)
        v.add_passphrase_wrapping(OTHER, kdf=WEAK_KDF)
        v.save()
        old_copy = self.dir / "old.vaultline"
        old_copy.write_bytes(self.path.read_bytes())

        v.remove_wrapping(1)
        v.save()
        self.assertEqual(vaultline.Vault.open(old_copy, OTHER).secrets,
                         {"GITHUB": "hunter2"})


class EnvelopeTests(VaultCase):
    """What a stranger holding the file can read."""

    def test_peek_needs_no_passphrase(self):
        self.make(hint="the usual three words, winter variant")
        peeked = vaultline.Vault.peek(self.path)
        self.assertEqual(peeked["hint"], "the usual three words, winter variant")
        self.assertEqual(peeked["format"], "vaultline")

    def test_peek_exposes_no_inventory(self):
        # The envelope must not say what is inside, how much of it there is,
        # or which services it is for. That is the reconnaissance.
        self.make(secrets={"REGISTRAR": "x", "MAILBOX": "y", "BANK": "z"})
        blob = json.dumps(vaultline.Vault.peek(self.path))
        for name in ("REGISTRAR", "MAILBOX", "BANK", "x", "y", "z"):
            self.assertNotIn(name, blob)
        self.assertNotIn("payload", vaultline.Vault.peek(self.path))

    def test_peek_does_not_leak_the_number_of_secrets(self):
        few = vaultline.Vault.peek(self.path) if self.path.exists() else None
        self.make(secrets={str(i): "v" for i in range(20)})
        peeked = vaultline.Vault.peek(self.path)
        self.assertNotIn("count", peeked)
        self.assertNotIn("secrets", peeked)
        del few

    def test_the_hint_survives_a_save(self):
        v = self.make(hint="first")
        v2 = vaultline.Vault.open(self.path, PASS)
        self.assertEqual(v2.hint, "first")
        v2.set_hint("second")
        v2.save()
        self.assertEqual(vaultline.Vault.peek(self.path)["hint"], "second")
        del v

    def test_a_future_format_version_is_refused_not_guessed_at(self):
        self.make()
        env = json.loads(self.path.read_text(encoding="utf-8"))
        env["version"] = vaultline.FORMAT_VERSION + 1
        self.path.write_text(json.dumps(env), encoding="utf-8")
        with self.assertRaises(vaultline.BadEnvelope):
            vaultline.Vault.open(self.path, PASS)

    def test_a_file_with_no_wrappings_is_refused(self):
        self.make()
        env = json.loads(self.path.read_text(encoding="utf-8"))
        env["wrappings"] = []
        self.path.write_text(json.dumps(env), encoding="utf-8")
        with self.assertRaises(vaultline.BadEnvelope):
            vaultline.Vault.open(self.path, PASS)

    def test_something_that_is_not_a_vault_is_refused(self):
        self.path.write_text('{"hello": "world"}', encoding="utf-8")
        with self.assertRaises(vaultline.BadEnvelope):
            vaultline.Vault.open(self.path, PASS)

    def test_a_tampered_payload_is_detected(self):
        # GPG owns the integrity check; this asserts we surface it rather than
        # returning whatever fell out.
        self.make()
        env = json.loads(self.path.read_text(encoding="utf-8"))
        body = env["payload"].splitlines()
        body[3] = ("A" * len(body[3])) if len(body) > 4 else body[3]
        env["payload"] = "\n".join(body)
        self.path.write_text(json.dumps(env), encoding="utf-8")
        with self.assertRaises(vaultline.VaultlineError):
            vaultline.Vault.open(self.path, PASS)


class SaveTests(VaultCase):
    def test_a_backup_is_left_behind(self):
        self.make()
        v = vaultline.Vault.open(self.path, PASS)
        v.secrets["X"] = "1"
        backup = v.save()
        self.assertTrue(backup.exists())

    def test_no_temporary_file_survives_a_good_save(self):
        self.make()
        self.assertFalse((self.dir / "test.vaultline.new").exists())

    def test_the_first_save_leaves_no_backup(self):
        v = vaultline.Vault.create(self.path, PASS, kdf=WEAK_KDF, secrets={})
        self.assertIsNone(v.save())


class LocationTests(VaultCase):
    """A vault under a synced folder is an off-site copy nobody chose to make."""

    def test_a_synced_looking_path_is_refused(self):
        synced = self.dir / "OneDrive" / "vault.vaultline"
        synced.parent.mkdir()
        with self.assertRaises(vaultline.UnsafeLocation):
            vaultline.Vault.create(synced, PASS, kdf=WEAK_KDF)

    def test_each_marker_is_caught(self):
        for marker in ("Dropbox", "iCloud Drive", "Nextcloud", "MySync"):
            with self.subTest(marker=marker):
                d = self.dir / marker
                d.mkdir(exist_ok=True)
                with self.assertRaises(vaultline.UnsafeLocation):
                    vaultline.Vault.create(d / "v.vaultline", PASS, kdf=WEAK_KDF)

    def test_the_override_is_explicit(self):
        synced = self.dir / "Dropbox2" / "vault.vaultline"
        synced.parent.mkdir()
        v = vaultline.Vault.create(synced, PASS, kdf=WEAK_KDF, override_sync=True)
        v.save(override_sync=True)
        self.assertTrue(synced.exists())

    def test_an_ordinary_path_is_allowed(self):
        vaultline.refuse_sync_root(self.dir / "plain" / "v.vaultline")


class KdfTests(unittest.TestCase):
    """The derivation itself, including the real parameters once."""

    def test_stretch_is_deterministic(self):
        a = vaultline.stretch(PASS, b"\x00" * 16, WEAK_KDF)
        b = vaultline.stretch(PASS, b"\x00" * 16, WEAK_KDF)
        self.assertEqual(a, b)

    def test_a_different_salt_gives_a_different_key(self):
        a = vaultline.stretch(PASS, b"\x00" * 16, WEAK_KDF)
        b = vaultline.stretch(PASS, b"\x01" * 16, WEAK_KDF)
        self.assertNotEqual(a, b)

    def test_a_different_passphrase_gives_a_different_key(self):
        a = vaultline.stretch(PASS, b"\x00" * 16, WEAK_KDF)
        b = vaultline.stretch(OTHER, b"\x00" * 16, WEAK_KDF)
        self.assertNotEqual(a, b)

    def test_an_unknown_kdf_is_refused_rather_than_defaulted(self):
        with self.assertRaises(vaultline.BadEnvelope):
            vaultline.stretch(PASS, b"\x00" * 16, {"kdf": "pbkdf2"})

    def test_the_shipped_parameters_are_memory_hard(self):
        # The defaults are what protect a real file. Asserting the shape means
        # a later "let's speed this up" cannot quietly reduce it to nothing.
        kdf = vaultline.default_kdf()
        self.assertEqual(kdf["kdf"], "scrypt")
        self.assertGreaterEqual(kdf["n"], 2 ** 16)
        self.assertGreaterEqual(kdf["r"], 8)
        self.assertGreaterEqual(kdf["n"] * kdf["r"] * 128, 64 * 1024 * 1024)

    @unittest.skipIf("--fast" in sys.argv, "slow: real KDF parameters")
    def test_the_real_parameters_work_and_cost_something(self):
        import time

        t0 = time.monotonic()
        key = vaultline.stretch(PASS, b"\x00" * 16)
        elapsed = time.monotonic() - t0
        self.assertTrue(key)
        self.assertGreater(elapsed, 0.02, "the real KDF is suspiciously cheap")


class Verifier:
    """A scripted stand-in for asking a service which value it accepts.

    Returns True, False or None per call, in order. None means *could not
    tell* - a network failure is not evidence, and the vault must not treat
    it as any.
    """

    def __init__(self, *results):
        self.results = list(results)
        self.asked = []

    def __call__(self, value):
        self.asked.append(value)
        return self.results.pop(0) if self.results else False


class RotationTests(VaultCase):
    """The state machine. Every rule here exists to stop one thing: a service
    accepting a new value while the record of it is lost."""

    def setUp(self):
        super().setUp()
        self.make(secrets={"REGISTRAR": "old-value"})
        self.v = vaultline.Vault.open(self.path, PASS)

    def reopened(self):
        return vaultline.Vault.open(self.path, PASS)

    # -- starting --------------------------------------------------------

    def test_the_candidate_is_on_disk_before_anything_is_submitted(self):
        # The ordering is the whole point: a crash after submission must never
        # find the candidate missing.
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.assertEqual(self.reopened().pending("REGISTRAR"), "new-value")

    def test_the_previous_value_is_kept_alongside(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        r = self.reopened().rotation("REGISTRAR")
        self.assertEqual(r["previous"], "old-value")
        self.assertEqual(self.reopened().secrets["REGISTRAR"], "old-value")

    def test_a_second_rotation_is_refused_while_one_is_in_flight(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        with self.assertRaises(vaultline.RotationError):
            self.v.begin_rotation("REGISTRAR", "newer-value")

    def test_an_empty_candidate_is_refused(self):
        with self.assertRaises(vaultline.RotationError):
            self.v.begin_rotation("REGISTRAR", "")

    # -- classifying the submission --------------------------------------

    def test_rejected_discards_the_candidate_and_leaves_the_old_value(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.v.record_outcome("REGISTRAR", "rejected")
        self.assertEqual(self.reopened().rotation_state("REGISTRAR"), vaultline.NONE)
        self.assertEqual(self.reopened().secrets["REGISTRAR"], "old-value")

    def test_unknown_keeps_both_values(self):
        """The case that motivates the whole design.

        A service can apply a change and lose the response. Reading that as
        failure - discarding the candidate - leaves only the value that no
        longer works.
        """
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.v.record_outcome("REGISTRAR", "unknown")
        r = self.reopened()
        self.assertEqual(r.rotation_state("REGISTRAR"), vaultline.UNKNOWN)
        self.assertEqual(r.pending("REGISTRAR"), "new-value")
        self.assertEqual(r.secrets["REGISTRAR"], "old-value")

    def test_accepted_is_not_activation(self):
        # Services truncate and normalise. Acceptance of a form is not proof
        # of what is now in force.
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.v.record_outcome("REGISTRAR", "accepted")
        r = self.reopened()
        self.assertEqual(r.rotation_state("REGISTRAR"), vaultline.ACCEPTED)
        self.assertEqual(r.secrets["REGISTRAR"], "old-value")

    def test_an_unknown_outcome_word_is_refused(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        with self.assertRaises(vaultline.RotationError):
            self.v.record_outcome("REGISTRAR", "probably-fine")

    def test_classifying_without_a_rotation_is_refused(self):
        with self.assertRaises(vaultline.RotationError):
            self.v.record_outcome("REGISTRAR", "accepted")

    # -- verification ----------------------------------------------------

    def test_a_verified_candidate_becomes_the_value(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.v.record_outcome("REGISTRAR", "accepted")
        self.assertEqual(self.v.verify("REGISTRAR", Verifier(True)), "active")
        r = self.reopened()
        self.assertEqual(r.secrets["REGISTRAR"], "new-value")
        self.assertEqual(r.rotation_state("REGISTRAR"), vaultline.NONE)

    def test_a_change_that_did_not_take_is_rolled_back(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.v.record_outcome("REGISTRAR", "unknown")
        # candidate fails, previous works: the service never applied it.
        self.assertEqual(self.v.verify("REGISTRAR", Verifier(False, True)),
                         vaultline.NONE)
        r = self.reopened()
        self.assertEqual(r.secrets["REGISTRAR"], "old-value")
        self.assertEqual(r.rotation_state("REGISTRAR"), vaultline.NONE)

    def test_an_inconclusive_verifier_changes_nothing(self):
        # A network failure is not evidence. Treating it as one is the same
        # mistake as treating an ambiguous submission as failure.
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.v.record_outcome("REGISTRAR", "unknown")
        self.assertEqual(self.v.verify("REGISTRAR", Verifier(None)),
                         vaultline.UNKNOWN)
        r = self.reopened()
        self.assertEqual(r.rotation_state("REGISTRAR"), vaultline.UNKNOWN)
        self.assertEqual(r.pending("REGISTRAR"), "new-value")
        self.assertEqual(r.secrets["REGISTRAR"], "old-value")

    def test_both_failing_locks_out_and_deletes_nothing(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.v.record_outcome("REGISTRAR", "unknown")
        with self.assertRaises(vaultline.LockedOut):
            self.v.verify("REGISTRAR", Verifier(False, False))
        r = self.reopened()
        self.assertEqual(r.rotation_state("REGISTRAR"), vaultline.LOCKED_OUT)
        self.assertEqual(r.pending("REGISTRAR"), "new-value")
        self.assertEqual(r.rotation("REGISTRAR")["previous"], "old-value")
        self.assertEqual(r.secrets["REGISTRAR"], "old-value")

    def test_the_vault_asks_the_candidate_first(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.v.record_outcome("REGISTRAR", "accepted")
        verifier = Verifier(True)
        self.v.verify("REGISTRAR", verifier)
        self.assertEqual(verifier.asked, ["new-value"])

    def test_verification_before_classification_is_refused(self):
        self.v.begin_rotation("REGISTRAR", "new-value")
        with self.assertRaises(vaultline.RotationError):
            self.v.verify("REGISTRAR", Verifier(True))

    # -- retry limits ----------------------------------------------------

    def test_attempts_are_counted_and_persisted(self):
        self.v.begin_rotation("REGISTRAR", "new-value", max_attempts=4)
        self.v.record_outcome("REGISTRAR", "unknown")
        self.v.verify("REGISTRAR", Verifier(None))
        self.assertEqual(self.reopened().rotation("REGISTRAR")["attempts"], 1)
        self.assertEqual(self.reopened().attempts_remaining("REGISTRAR"), 3)

    def test_verification_stops_rather_than_risking_lockout(self):
        # A wrong guess can lock an account, so exhausting the budget must
        # stop the tool rather than let it keep trying.
        self.v.begin_rotation("REGISTRAR", "new-value", max_attempts=2)
        self.v.record_outcome("REGISTRAR", "unknown")
        self.v.verify("REGISTRAR", Verifier(None))
        self.v.verify("REGISTRAR", Verifier(None))
        self.assertEqual(self.v.attempts_remaining("REGISTRAR"), 0)
        with self.assertRaises(vaultline.RotationError):
            self.v.verify("REGISTRAR", Verifier(True))

    def test_it_will_not_test_the_previous_value_without_budget(self):
        # Falling back to the old value is itself an attempt.
        self.v.begin_rotation("REGISTRAR", "new-value", max_attempts=1)
        self.v.record_outcome("REGISTRAR", "unknown")
        with self.assertRaises(vaultline.RotationError):
            self.v.verify("REGISTRAR", Verifier(False, True))
        self.assertEqual(self.reopened().pending("REGISTRAR"), "new-value")

    # -- the work list ---------------------------------------------------

    def test_mid_rotation_lists_what_is_in_flight(self):
        self.v.secrets["MAILBOX"] = "m"
        self.v.begin_rotation("REGISTRAR", "new-value")
        self.assertEqual(list(self.v.mid_rotation()), ["REGISTRAR"])
        self.v.record_outcome("REGISTRAR", "rejected")
        self.assertEqual(self.v.mid_rotation(), {})


class PayloadTests(VaultCase):
    def test_a_version_0_bare_mapping_still_opens(self):
        # Files written before the payload became a document must not become
        # unreadable, or the format has broken its own promise once already.
        self.make(secrets={"A": "1"})
        v = vaultline.Vault.open(self.path, PASS)
        legacy = json.dumps({"A": "1"}).encode("utf-8")
        env = json.loads(self.path.read_text(encoding="utf-8"))
        env["payload"] = vaultline._encrypt(legacy, v._master)
        self.path.write_text(json.dumps(env), encoding="utf-8")

        reopened = vaultline.Vault.open(self.path, PASS)
        self.assertEqual(reopened.secrets, {"A": "1"})
        self.assertEqual(reopened.rotations, {})

    def test_a_future_payload_version_is_refused(self):
        self.make()
        v = vaultline.Vault.open(self.path, PASS)
        future = json.dumps({"payload_version": vaultline.PAYLOAD_VERSION + 1,
                             "secrets": {}}).encode("utf-8")
        env = json.loads(self.path.read_text(encoding="utf-8"))
        env["payload"] = vaultline._encrypt(future, v._master)
        self.path.write_text(json.dumps(env), encoding="utf-8")
        with self.assertRaises(vaultline.BadEnvelope):
            vaultline.Vault.open(self.path, PASS)

    def test_rotation_state_is_inside_the_encryption(self):
        self.make(secrets={"REGISTRAR": "old"})
        v = vaultline.Vault.open(self.path, PASS)
        v.begin_rotation("REGISTRAR", "a-distinctive-candidate")
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("a-distinctive-candidate", raw)
        self.assertNotIn("REGISTRAR", raw)


class GpgPathTests(unittest.TestCase):
    """Finding gpg. This is not incidental plumbing.

    GPG ships with Git, but Git adds it to PATH only inside Git Bash - so the
    library worked in one shell and failed in the one most people use, with an
    error that said only "the system cannot find the file specified". Silent
    environment differences are exactly the failure mode worth a test.
    """

    def setUp(self):
        import os

        self._saved = os.environ.pop("VAULTLINE_GPG", None)

    def tearDown(self):
        import os

        os.environ.pop("VAULTLINE_GPG", None)
        if self._saved is not None:
            os.environ["VAULTLINE_GPG"] = self._saved

    def test_it_finds_something_that_exists(self):
        if not gpg_available():
            self.skipTest("gpg is not installed at all")
        self.assertTrue(pathlib.Path(vaultline.gpg_path()).exists())

    def test_an_override_is_honoured(self):
        import os

        os.environ["VAULTLINE_GPG"] = sys.executable
        self.assertEqual(vaultline.gpg_path(), sys.executable)

    def test_an_override_pointing_nowhere_says_so(self):
        import os

        os.environ["VAULTLINE_GPG"] = str(pathlib.Path(tempfile.gettempdir()) / "nope.exe")
        with self.assertRaises(vaultline.VaultlineError) as caught:
            vaultline.gpg_path()
        self.assertIn("VAULTLINE_GPG", str(caught.exception))

    def test_the_not_found_message_is_actionable(self):
        # An error that names the fix is the difference between a five-minute
        # problem and an afternoon.
        import os
        import shutil

        real_which = shutil.which
        shutil.which = lambda *a, **k: None
        real_fallbacks = vaultline.GPG_FALLBACKS
        vaultline.GPG_FALLBACKS = ()
        try:
            os.environ.pop("VAULTLINE_GPG", None)
            with self.assertRaises(vaultline.VaultlineError) as caught:
                vaultline.gpg_path()
            message = str(caught.exception)
            self.assertIn("VAULTLINE_GPG", message)
            self.assertIn("Git Bash", message)
        finally:
            shutil.which = real_which
            vaultline.GPG_FALLBACKS = real_fallbacks


class VersionTests(unittest.TestCase):
    def test_version_is_a_string(self):
        self.assertIsInstance(vaultline.__version__, str)

    def test_format_is_named_and_versioned(self):
        self.assertEqual(vaultline.FORMAT, "vaultline")
        self.assertIsInstance(vaultline.FORMAT_VERSION, int)


def main(argv=None):
    parser = argparse.ArgumentParser(description="vaultline development tooling")
    sub = parser.add_subparsers(dest="command")
    test = sub.add_parser("test", help="run the test suite")
    test.add_argument("-v", "--verbose", action="store_true")
    test.add_argument("--fast", action="store_true", help="skip the slow KDF case")
    args = parser.parse_args(argv)

    verbosity = 2 if getattr(args, "verbose", False) else 1
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        import traceback

        print("FATAL unhandled exception:\n%s" % traceback.format_exc(),
              file=sys.stderr)
        raise
