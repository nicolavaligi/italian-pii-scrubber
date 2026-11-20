# itscrub — Italian personal data scrubber

Find and mask **Italian personal data** in logs, text files and source code:
codice fiscale, partita IVA, IBAN, e-mail and PEC addresses, phone numbers,
licence plates and tessera sanitaria numbers.

One Python file, standard library only, nothing leaves your machine.

```console
$ echo "login RSSMRA80A01H501U da mario.rossi@posta.example, cell +39 333 1234567" | itscrub mask
login [CODICE_FISCALE] da [EMAIL], cell [TELEFONO]

$ itscrub scan src/
src/import.py:42:11: codice_fiscale (high) RS************1U
src/fixtures/clienti.csv:3:18: iban (high) IT***********************56
itscrub: 2 finding(s) in 2 file(s), 37 scanned
```

*(Every identifier in this README is invented test data.)*

## Why

GDPR asks you to keep personal data out of places where it is not needed —
application logs and git history being the two where it most often ends up by
accident. Generic secret scanners do not know what a codice fiscale is, and
generic PII tools are heavy to install in a commit hook.

`itscrub` does one thing: it knows the Italian formats and **verifies the check
digit** wherever one exists, so an arbitrary 11-digit order number is not
reported as a partita IVA. That keeps noise low enough to run it on every commit.

| Detector | What it matches | Verification |
|---|---|---|
| `codice_fiscale` | 16-character personal tax code, omocodia included | check letter |
| `partita_iva` | 11 digits, optional `IT` prefix | check digit |
| `iban` | Italian IBAN, with or without spaces | mod-97 |
| `pec` | certified e-mail, recognised by provider domain | — |
| `email` | e-mail address | — |
| `telefono` | mobile and landline, with or without `+39` | prefix / nearby words |
| `targa` | licence plate, current `AA 000 AA` format | nearby words |
| `tessera_sanitaria` | 20 digits starting with `80380` | prefix |

## Install

No installation needed — copy `itscrub.py` and run it:

```bash
python3 itscrub.py scan .
```

Or install the `itscrub` command (Python 3.9+, no dependencies):

```bash
pip install git+https://github.com/nicolavaligi/italian-pii-scrubber
```

## Three ways to use it

### 1. Block personal data before it is committed

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/nicolavaligi/italian-pii-scrubber
    rev: v0.1.0
    hooks:
      - id: itscrub
```

In CI, `itscrub scan . --format github` prints GitHub Actions annotations and
exits with status 1 when something is found.

`scan` never prints what it found in full — the report itself would otherwise
become a leak in your CI logs. Values are shown partially masked; add
`--show-values` when you need to see them locally.

### 2. Clean a log stream or a file

```bash
tail -f app.log | itscrub mask                 # live
itscrub mask export.csv -o export.clean.csv
itscrub mask --in-place old.log
```

Three masking styles (`--style`):

| Style | Output | Use it when |
|---|---|---|
| `placeholder` (default) | `[CODICE_FISCALE]` | you only need the value gone |
| `partial` | `RS************1U` | a human needs a hint to recognise the record |
| `hash` | `[CODICE_FISCALE:3f9a1c0b77de]` | you need to follow the same person across lines without knowing who it is |

`hash` is a keyed HMAC-SHA256 and requires a secret in the `ITSCRUB_SALT`
environment variable. Without a secret key the tokens could be reversed by
simply hashing every possible codice fiscale, so the tool refuses to run.

### 3. Keep it out of your Python logs in the first place

```python
import logging
from itscrub import ScrubFilter

handler = logging.StreamHandler()
handler.addFilter(ScrubFilter())          # or ScrubFilter(style="hash")
logging.getLogger().addHandler(handler)

logging.warning("pagamento da %s su %s", "RSSMRA80A01H501U", "IT60X0542811101000000123456")
# pagamento da [CODICE_FISCALE] su [IBAN]
```

Also available: `scrub(text)` returns the masked text, `find(text)` returns the
findings with kind, confidence, line and column.

## Confidence

Every finding is `high`, `medium` or `low`:

- **high** — the check digit is correct, or the value has an explicit prefix
  (`+39`, `IT`) or a telling word right before it (`p.iva`, `cell`, `targa` …);
- **medium** — the shape is specific but there is no check digit (e-mail, a
  phone number written with separators, a partita IVA with no hint around it);
- **low** — the shape alone: ten bare digits starting with 3, a plate-like
  token, a codice fiscale or IBAN whose check digit is *wrong*.

The two commands have different defaults on purpose. `scan` acts from `medium`,
because a commit hook that cries wolf gets disabled. `mask` acts from `low`,
because in a log a missed phone number costs more than an over-masked ID.
Change either with `--min-confidence`.

## Silencing false positives

- **One line:** add `itscrub: ignore` in a comment on that line (scan only).
- **Known values:** an allowlist file, `.itscrub-allow` in the working directory
  or `--allow FILE`. One entry per line: a literal value, or `re:<regex>`.

  ```text
  # our own public company data
  01234567897
  re:@acme\.example$
  ```

  Do not put real people's data in the allowlist — the file is committed too.
- **Paths:** `--exclude 'tests/fixtures/*'` (repeatable).
- **One detector only:** `--kinds codice_fiscale,iban`.

Already ignored by default: `example.com`-style domains, `noreply@…`,
`git@host`, GitHub noreply addresses, and file names such as `logo@2x.png`
(`--no-default-allow` turns this off). Directories like `.git`, `node_modules`
and `.venv`, binary files and files over 5 MB are skipped.

## Privacy and GDPR notes

- **Everything is local.** No network calls, no telemetry, no files written
  except the output you ask for.
- **Masking is not anonymisation.** `partial` keeps part of the value, and
  `hash` is *pseudonymisation* (GDPR art. 4(5)): the output is still personal
  data for whoever holds the key. Treat `ITSCRUB_SALT` as a secret and rotate it
  if it leaks.
- **It reduces risk; it does not certify anything.** Names, addresses, dates of
  birth and free-text descriptions are not detected. A clean scan means "none of
  these eight identifiers were found", nothing more.
- Scanning does not remove data that is already in your git history; that takes
  a history rewrite.

## Limits

- Works line by line: a value split across two lines is not seen.
- Names and postal addresses are out of scope (they need language models, not
  patterns). For that, look at [Microsoft Presidio](https://github.com/microsoft/presidio),
  which also has Italian recognisers; `itscrub` trades that breadth for zero
  dependencies and a start-up time measured in milliseconds.
- Plates: only the format in use since 1994. Phone numbers: Italian numbering only.
- A partita IVA check digit is a single digit, so one random 11-digit number in
  ten passes it. Without a hint nearby such a match is reported as `medium`.

## Development

```bash
python3 -m unittest discover -s tests -v
```

The stack is deliberately plain Python standard library: a hook that runs on
every commit must install instantly and start fast, and a privacy tool is
easier to trust when it is one readable file with no dependencies to audit.

## In breve (italiano)

`itscrub` trova e maschera i dati personali italiani — codice fiscale, partita
IVA, IBAN, e-mail e PEC, telefoni, targhe, tessera sanitaria — nei log e nel
codice. Verifica i caratteri di controllo, quindi segnala poco rumore. Si usa
come hook pre-commit (`itscrub scan`), come filtro sui log (`itscrub mask`) o
come filtro del modulo `logging` di Python (`ScrubFilter`). Tutto resta sulla
tua macchina. Attenzione: mascherare non equivale ad anonimizzare.

## License

MIT
