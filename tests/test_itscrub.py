"""Tests for itscrub. Every identifier below is invented test data."""
import contextlib
import io
import json
import logging
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import itscrub  # noqa: E402
from itscrub import HIGH, LOW, MEDIUM, Allowlist, ScrubFilter, find, scrub  # noqa: E402

CF = "RSSMRA80A01H501U"
PIVA = "01234567897"
IBAN = "IT60X0542811101000000123456"
TS = "80380000900123456789"


def kinds(text, conf=MEDIUM, **kw):
    return [(f.kind, f.value) for f in find(text, conf, **kw)]


def run(argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("sys.stdin", io.StringIO(stdin)), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = itscrub.main(argv)
    return code, out.getvalue(), err.getvalue()


class CheckDigits(unittest.TestCase):
    def test_codice_fiscale(self):
        self.assertTrue(itscrub.cf_is_valid(CF))
        self.assertTrue(itscrub.cf_is_valid(CF.lower()))
        self.assertFalse(itscrub.cf_is_valid("RSSMRA80A01H501X"))
        self.assertFalse(itscrub.cf_is_valid("RSSMRA80A01H501"))
        self.assertFalse(itscrub.cf_is_valid("RSSMRA80A01H50-U"))

    def test_codice_fiscale_omocodia(self):
        # last digit replaced by its letter (1 -> M): the check letter changes
        base = "RSSMRA80A01H50M"
        valid = [base + c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if itscrub.cf_is_valid(base + c)]
        self.assertEqual(len(valid), 1)
        self.assertEqual(kinds(valid[0]), [("codice_fiscale", valid[0])])

    def test_partita_iva(self):
        self.assertTrue(itscrub.piva_is_valid(PIVA))
        self.assertTrue(itscrub.piva_is_valid("12345678903"))
        self.assertFalse(itscrub.piva_is_valid("01234567890"))
        self.assertFalse(itscrub.piva_is_valid("00000000000"))
        self.assertFalse(itscrub.piva_is_valid("0123456789"))
        self.assertFalse(itscrub.piva_is_valid("0123456789A"))

    def test_iban(self):
        self.assertTrue(itscrub.iban_is_valid(IBAN))
        self.assertTrue(itscrub.iban_is_valid("IT60 X054 2811 1010 0000 0123 456"))
        self.assertFalse(itscrub.iban_is_valid("IT61X0542811101000000123456"))
        self.assertFalse(itscrub.iban_is_valid("DE89370400440532013000"))


class Detection(unittest.TestCase):
    def test_codice_fiscale(self):
        self.assertEqual(kinds("utente %s creato" % CF), [("codice_fiscale", CF)])
        self.assertEqual(kinds("cf=%s;" % CF.lower()), [("codice_fiscale", CF.lower())])

    def test_codice_fiscale_wrong_check_is_low(self):
        bad = "RSSMRA80A01H501X"
        self.assertEqual(kinds(bad), [])
        self.assertEqual(kinds(bad, LOW), [("codice_fiscale", bad)])

    def test_sixteen_letter_word_is_not_a_code(self):
        self.assertEqual(kinds("ABCDEFLMALMALMNA", LOW), [])

    def test_not_inside_longer_token(self):
        self.assertEqual(kinds("X" + CF, LOW), [])
        self.assertEqual(kinds(CF + "9", LOW), [])

    def test_partita_iva_confidence(self):
        self.assertEqual(find(PIVA)[0].confidence, MEDIUM)
        self.assertEqual(find("P.IVA " + PIVA)[0].confidence, HIGH)
        self.assertEqual(find("partita iva: " + PIVA)[0].confidence, HIGH)
        self.assertEqual(find("IT" + PIVA)[0].confidence, HIGH)
        self.assertEqual(find("IT" + PIVA)[0].value, "IT" + PIVA)

    def test_eleven_digits_with_wrong_check_ignored(self):
        self.assertEqual(kinds("order 01234567890", LOW), [])

    def test_iban_plain_and_spaced(self):
        self.assertEqual(kinds("bonifico su " + IBAN), [("iban", IBAN)])
        spaced = "IT60 X054 2811 1010 0000 0123 456"
        self.assertEqual(kinds("IBAN: %s." % spaced), [("iban", spaced)])

    def test_iban_is_one_finding_not_fragments(self):
        self.assertEqual(len(find(IBAN, LOW)), 1)

    def test_email_and_pec(self):
        self.assertEqual(kinds("scrivi a mario.rossi@posta.example"),
                         [("email", "mario.rossi@posta.example")])
        self.assertEqual(kinds("studio@pec.posta.example"), [("pec", "studio@pec.posta.example")])
        self.assertEqual(kinds("ditta@legalmail.example"), [("pec", "ditta@legalmail.example")])
        self.assertEqual(kinds("ufficio@pec.comune.example"),
                         [("pec", "ufficio@pec.comune.example")])

    def test_email_false_positives(self):
        for text in ("logo@2x.png", "git@github.com:org/repo.git", "user@example.com",
                     "noreply@acme.it", "react@18.3.1", "1234+abc@users.noreply.github.com",
                     "a@b.test"):
            self.assertEqual(kinds(text, LOW), [], text)

    def test_mobile_confidence(self):
        self.assertEqual(find("+39 333 1234567", LOW)[0].confidence, HIGH)
        self.assertEqual(find("00393331234567", LOW)[0].confidence, HIGH)
        self.assertEqual(find("cell. 3331234567", LOW)[0].confidence, HIGH)
        self.assertEqual(find("333 1234567", LOW)[0].confidence, MEDIUM)
        self.assertEqual(find("3331234567", LOW)[0].confidence, LOW)
        self.assertEqual(kinds("3331234567"), [])

    def test_phone_not_in_decimals_or_longer_numbers(self):
        for text in ("0.3331234567", "1,3331234567", "33312345678901", "id3331234567"):
            self.assertEqual(kinds(text, LOW), [], text)

    def test_landline(self):
        self.assertEqual(kinds("+39 06 12345678"), [("telefono", "+39 06 12345678")])
        self.assertEqual(kinds("tel 06 12345678"), [("telefono", "06 12345678")])
        self.assertEqual(kinds("valore 06 12345678", LOW), [])

    def test_plate_needs_context(self):
        self.assertEqual(kinds("AB123CD"), [])
        self.assertEqual(kinds("AB123CD", LOW), [("targa", "AB123CD")])
        self.assertEqual(kinds("targa AB 123 CD"), [("targa", "AB 123 CD")])
        self.assertEqual(kinds("ab123cd", LOW), [])
        self.assertEqual(kinds("IO123QU", LOW), [])      # letters never used on plates

    def test_tessera_sanitaria(self):
        self.assertEqual(kinds(TS), [("tessera_sanitaria", TS)])
        self.assertEqual(find("tessera sanitaria " + TS)[0].confidence, HIGH)
        self.assertEqual(kinds("80381000900123456789", LOW), [])

    def test_positions(self):
        f = find("riga uno\n  cf %s\n" % CF)[0]
        self.assertEqual((f.line, f.col), (2, 6))
        text = "riga uno\n  cf %s\n" % CF
        self.assertEqual(text[f.start:f.end], CF)

    def test_kinds_filter(self):
        text = "%s mario@posta.example" % CF
        self.assertEqual(kinds(text, kinds=["email"]), [("email", "mario@posta.example")])
        with self.assertRaises(ValueError):
            find(text, kinds=["passport"])

    def test_clean_text(self):
        text = "2026-11-20 10:31:02 INFO request 8f3a2b took 132ms status=200 size=10485760"
        self.assertEqual(kinds(text, LOW), [])


class Masking(unittest.TestCase):
    def test_placeholder(self):
        self.assertEqual(scrub("cf %s ok" % CF), "cf [CODICE_FISCALE] ok")

    def test_keeps_everything_else(self):
        text = "a\r\nb %s\n\nc\tfine" % PIVA
        self.assertEqual(scrub(text), "a\r\nb [PARTITA_IVA]\n\nc\tfine")

    def test_partial(self):
        self.assertEqual(scrub(CF, "partial"), "RS************1U")
        self.assertEqual(scrub("mario.rossi@posta.example", "partial"), "m***@posta.example")
        self.assertNotIn(CF, scrub(CF, "partial"))

    def test_hash_is_stable_and_keyed(self):
        a = scrub("x %s y %s" % (CF, CF.lower()), "hash", salt="k1")
        tokens = [t for t in a.split() if t.startswith("[")]
        self.assertEqual(tokens[0], tokens[1])
        self.assertTrue(tokens[0].startswith("[CODICE_FISCALE:"))
        self.assertNotEqual(a, scrub("x %s y %s" % (CF, CF.lower()), "hash", salt="k2"))
        self.assertNotIn(CF, a)

    def test_hash_needs_salt(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(itscrub.SALT_ENV, None)
            with self.assertRaises(ValueError):
                scrub(CF, "hash")

    def test_hash_salt_from_environment(self):
        with mock.patch.dict(os.environ, {itscrub.SALT_ENV: "k1"}):
            self.assertEqual(scrub(CF, "hash"), scrub(CF, "hash", salt="k1"))

    def test_unknown_style(self):
        with self.assertRaises(ValueError):
            scrub(CF, "rot13")

    def test_mask_default_catches_low_confidence(self):
        self.assertEqual(scrub("3331234567"), "[TELEFONO]")
        self.assertEqual(scrub("3331234567", min_confidence=MEDIUM), "3331234567")


class Allow(unittest.TestCase):
    def test_literal_ignores_case_and_spacing(self):
        allow = Allowlist(["# comment", "", "it60 x054 2811 1010 0000 0123 456"])
        self.assertEqual(find(IBAN, allow=allow), [])

    def test_regex(self):
        allow = Allowlist([r"re:@acme\.example$"])
        self.assertEqual(kinds("info@acme.example mario@posta.example", allow=allow),
                         [("email", "mario@posta.example")])

    def test_defaults_can_be_disabled(self):
        self.assertEqual(kinds("user@example.com", allow=Allowlist(defaults=False)),
                         [("email", "user@example.com")])
        self.assertEqual(kinds("user@example.com", allow=None),
                         [("email", "user@example.com")])


class LoggingFilter(unittest.TestCase):
    def test_message_and_args_are_scrubbed(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(ScrubFilter())
        logger = logging.getLogger("itscrub.test")
        logger.propagate = False
        logger.addHandler(handler)
        try:
            logger.warning("login %s da %s", CF, "mario.rossi@posta.example")
        finally:
            logger.removeHandler(handler)
        self.assertEqual(stream.getvalue(), "login [CODICE_FISCALE] da [EMAIL]\n")

    def test_bad_configuration_fails_early(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(itscrub.SALT_ENV, None)
            with self.assertRaises(ValueError):
                ScrubFilter(style="hash")


class Cli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def write(self, name, content, mode="w"):
        path = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as fh:
            fh.write(content)
        return path

    def test_scan_clean_exits_zero(self):
        self.write("a.txt", "niente di personale\n")
        code, out, err = run(["scan", "."])
        self.assertEqual((code, out), (0, ""))
        self.assertIn("0 finding(s)", err)

    def test_scan_reports_without_leaking_values(self):
        self.write("src/a.py", "x = 1\ncf = '%s'\n" % CF)
        code, out, err = run(["scan", "."])
        self.assertEqual(code, 1)
        self.assertIn("a.py:2:7: codice_fiscale (high) RS************1U", out)
        self.assertNotIn(CF, out + err)

    def test_scan_show_values(self):
        self.write("a.txt", CF)
        self.assertIn(CF, run(["scan", "a.txt", "--show-values"])[1])

    def test_scan_json_and_github(self):
        self.write("a.txt", "mail mario@posta.example\n")
        code, out, _ = run(["scan", "a.txt", "--format", "json"])
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual((data[0]["kind"], data[0]["line"], data[0]["value"]),
                         ("email", 1, "m***@posta.example"))
        out = run(["scan", "a.txt", "--format", "github"])[1]
        self.assertTrue(out.startswith("::warning file=a.txt,line=1,col=6,title=itscrub email::"))

    def test_scan_stdin(self):
        code, out, _ = run(["scan", "-"], stdin="p.iva %s\n" % PIVA)
        self.assertEqual(code, 1)
        self.assertIn("<stdin>:1:7: partita_iva (high)", out)

    def test_inline_ignore(self):
        self.write("a.py", "cf = '%s'  # itscrub: ignore\n" % CF)
        self.assertEqual(run(["scan", "a.py"])[0], 0)

    def test_skips_binary_vendor_dirs_and_excludes(self):
        self.write("bin.dat", b"\x00\x01" + CF.encode(), "wb")
        self.write("node_modules/x/a.js", CF)
        self.write(".git/config", CF)
        self.write("fixtures/a.csv", CF)
        self.assertEqual(run(["scan", ".", "--exclude", "fixtures/*"])[0], 0)
        self.assertEqual(run(["scan", "."])[0], 1)

    def test_max_size(self):
        self.write("big.txt", CF + "\n" + "x" * 2000)
        self.assertEqual(run(["scan", ".", "--max-size", "1000"])[0], 0)

    def test_allow_file_picked_up_from_cwd(self):
        self.write("a.txt", CF)
        self.write(".itscrub-allow", "# test fixtures\n%s\n" % CF)
        self.assertEqual(run(["scan", "a.txt"])[0], 0)

    def test_min_confidence_and_kinds(self):
        self.write("a.txt", "3331234567 mario@posta.example\n")
        self.assertEqual(run(["scan", "a.txt", "--kinds", "telefono"])[0], 0)
        self.assertEqual(
            run(["scan", "a.txt", "--kinds", "telefono", "--min-confidence", "low"])[0], 1)
        self.assertEqual(run(["scan", "a.txt", "--kinds", "nope"])[0], 2)

    def test_unreadable_path_is_an_error(self):
        code, _, err = run(["scan", "missing.txt"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_mask_stdin(self):
        code, out, _ = run(["mask"], stdin="a %s\nb 3331234567\n" % CF)
        self.assertEqual((code, out), (0, "a [CODICE_FISCALE]\nb [TELEFONO]\n"))

    def test_mask_output_file_and_style(self):
        src = self.write("in.log", "cf %s\n" % CF)
        code, out, _ = run(["mask", src, "-o", "out.log", "--style", "partial"])
        self.assertEqual((code, out), (0, ""))
        with open("out.log", encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "cf RS************1U\n")

    def test_mask_in_place(self):
        src = self.write("app.log", "cf %s\r\nfine\r\n" % CF)
        self.assertEqual(run(["mask", "--in-place", src])[0], 0)
        with open(src, encoding="utf-8", newline="") as fh:
            self.assertEqual(fh.read(), "cf [CODICE_FISCALE]\r\nfine\r\n")
        self.assertEqual(sorted(os.listdir(self.tmp)), ["app.log"])

    def test_mask_hash_requires_salt(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(itscrub.SALT_ENV, None)
            self.assertEqual(run(["mask", "--style", "hash"], stdin=CF)[0], 2)
        with mock.patch.dict(os.environ, {itscrub.SALT_ENV: "s"}):
            code, out, _ = run(["mask", "--style", "hash"], stdin=CF)
            self.assertEqual(code, 0)
            self.assertRegex(out, r"^\[CODICE_FISCALE:[0-9a-f]{12}\]$")

    def test_kinds_and_no_command(self):
        code, out, _ = run(["kinds"])
        self.assertEqual(code, 0)
        self.assertEqual([l.split()[0] for l in out.splitlines()], list(itscrub.KINDS))
        self.assertEqual(run([])[0], 2)


if __name__ == "__main__":
    unittest.main()
