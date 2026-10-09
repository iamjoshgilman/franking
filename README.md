# phishlens

An interactive analysis lens for suspicious `.eml` files.

Most email tooling will happily print a header block and leave you to spot
what is wrong. phishlens does the cross-referencing: it checks claimed
authentication results against the rest of the message, compares what a link
says against where it goes, and looks inside archives at what is actually
being delivered. Then it tells you *why* each answer matters, not just what
it is.

```
  email.eml  Urgent: Invoice Payment Required - Overdue Notice
  24 findings · finance@business-finance.com · 1 attachment(s)
──────────────────────────────────────────────────────────────────────────────────────────
 ✗ Summary [24]      │ ✗ Double extension: invoice_docu…   │
 ✗ Findings [24]     │ ✗ Executable inside Invoice_2025…   │  Double extension: invoice_…
   Authentication…   │ ✗ dkim=pass claimed but no DKIM-…   │  CRITICAL
   Routing [3]       │ ✗ Authentication-Results has no …   │
   Originator › 13   │ ✗ ARC-Seal i=1 is not cv=none › 5   │  value
   URLs [1]          │ ✗ ARC-Message-Signature carries …   │  Double extension: invoice_…
   Attachments [1]   │ ✗ Body identifier does not match…   │
   Body [1]          │ ✗ SPF-authorised IP is absent fr…   │  why it matters
   Headers [25]      │ ⚠ Incomplete ARC set › 5            │  The file inside Invoice_20…
   IOCs › 13         │ ⚠ SPF verifier does not appear i…   │  'invoice_document.pdf.bat'…
 q Quit  ? Help  y Copy value  Y Copy section  a Copy IOCs  e Export JSON  / Search
```

## Why

A forged header is rarely wrong on its own terms. It is wrong *relative to
something else in the file*:

- `Authentication-Results` reports `dkim=pass`, but there is no
  `DKIM-Signature` header anywhere in the message. Nothing was verified.
- SPF authorises an IP address that appears in no `Received` hop. The
  address never connected.
- The first `ARC-Seal` claims `cv=pass`, which is impossible at `i=1`.
- The body cites invoice `INV-2025-0012` while the link carries
  `INV-2025-0987`. A real portal link is generated from the record it points
  at; a campaign's landing page is static.
- An attachment is named `invoice.pdf.bat`.

No parser flags a *missing* header, and none of these fall out of a field
dump. phishlens encodes 29 of these checks as rules, each one explaining its
own reasoning and tagged with the relevant MITRE ATT&CK technique.

## Install

```bash
uv tool install phishlens          # or: pipx install phishlens
```

From a clone:

```bash
git clone https://github.com/iamjoshgilman/phishlens
cd phishlens
uv tool install .                  # or: pip install -e '.[dev]'
```

## Use

```bash
phishlens message.eml              # interactive browser
phishlens message.eml --findings   # scrollback-friendly report
phishlens message.eml --iocs       # indicators, one per line
phishlens message.eml --json       # everything, machine-readable
phishlens message.eml --tree       # section outline
```

`--findings` exits non-zero when anything high or critical fired, so it drops
straight into a pipeline:

```bash
for f in samples/*.eml; do
  phishlens "$f" --findings --no-color --min-severity high || echo "FLAGGED: $f"
done
```

### Keys

| Key | Action |
| --- | --- |
| `j` / `k` | move |
| `l` / `→` / `⏎` | descend |
| `h` / `←` / `⌫` | ascend |
| `tab` | switch pane |
| `y` | copy the selected value |
| `Y` | copy the whole section |
| `a` | copy every extracted indicator |
| `/` | search labels, values and explanations |
| `f` | jump to Findings |
| `e` | export JSON next to the file |
| `?` | help |

`y` is the one to remember. Hashes and URLs are what you actually need out of
the tool, and retyping a SHA-256 is nobody's idea of analysis. Clipboard
writes go through `wl-copy`, `xclip`, `xsel`, `pbcopy` or `clip.exe`,
whichever exists, and fall back to OSC 52 so it still works over SSH.

## What it looks at

| Section | Contents |
| --- | --- |
| Summary | verdict, sender, recipient, originating IP, counts |
| Findings | every rule that fired, with evidence and ATT&CK IDs |
| Authentication | SPF, DKIM, DMARC, ARC, with the claims separated from the proof |
| Routing | the `Received` chain in transit order, hop by hop |
| Originator | From, Reply-To, Return-Path, `X-` headers, Message-ID |
| URLs | host, path, registrable domain, and the link text shown to the reader |
| Attachments | type, size, MD5/SHA-1/SHA-256, and names of files inside archives |
| Body | each MIME part, plus the HTML rendered down to text |
| Headers | every header in file order |
| IOCs | a flat, copy-ready indicator list |

Archives are read through their local file headers rather than `zipfile`, so
a truncated or deliberately damaged ZIP still gives up the filenames inside
it — which is usually the thing you actually wanted.

Addresses from RFC 5737 documentation ranges, RFC 1918 space and the
reserved `555-01xx` phone block are flagged as synthetic, so sample material
from training platforms does not quietly end up in a blocklist.

## Writing a rule

Rules live in `src/phishlens/rules/` and register themselves with a
decorator. A rule gets the parsed message and either stays quiet or emits
findings:

```python
@rule("CONT010", "Subject promises a refund", Severity.MEDIUM,
      mitre=["T1566"])
def refund_bait(doc, emit):
    if "refund" not in doc.subject.lower():
        return None
    return emit(
        "Unsolicited refund offers are a standard pretext for collecting "
        "card details on the landing page.",
        [Evidence("Subject", doc.subject)],
    )
```

Drop it in the right module and it appears everywhere — TUI, reports and
JSON — with no further wiring. The parser never judges and the rules never
parse, which keeps both testable.

Every rule should have a test proving it fires on `tests/fixtures/phish.eml`
**and** stays quiet on `tests/fixtures/clean.eml`. A rule that cannot stay
quiet is noise.

```bash
pytest
ruff check .
```

## Scope

phishlens reads files. It does not resolve DNS, fetch URLs, detonate
attachments or call out to any service, so it is safe to point at live
samples and it works offline. Verifying that a domain's SPF record really
authorises an address is deliberately out of scope — that needs the network,
and it is a different tool.

## Licence

MIT.
