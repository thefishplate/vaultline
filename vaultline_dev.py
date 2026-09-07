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
