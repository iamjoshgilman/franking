# franking

An interactive analysis lens for suspicious `.eml` files.

> A *franking mark* is the postmark that proves postage was genuinely paid.
> Forging one has been a crime since the penny post. This tool asks the same
> question of an email: are the marks it carries real, or just printed on?

Most email tooling will happily print a header block and leave you to spot
what is wrong. franking does the cross-referencing: it checks claimed
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
 q Quit  ? Help  y Copy  Y Copy section  a Copy IOCs  H Copy SHA-256  / Search  f Findings
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
- SPF and DKIM both pass — for `mailer-relay-7.example`, while the message
  displays as coming from `paypa1-security.example`. Authentication proves
  the sender controls *a* domain, never that it is the one the reader sees.
  This is what DMARC alignment exists to close.
- A link points at `xn--80ak6aa92e.example`, which renders as `аррӏе.example`
  in Cyrillic.
- An attachment is named `invoice.pdf.bat`.
- An archive is encrypted and the body supplies the password: the gateway
  cannot read it, the recipient can.

No parser flags a *missing* header, and none of these fall out of a field
dump. franking encodes 35 of these checks as rules, each one explaining its
own reasoning and tagged with the relevant MITRE ATT&CK technique.

## Forwarded reports

A reported phish rarely arrives as a bare `.eml`. It arrives attached to
"FW: is this legit?", and analysing the covering note describes the
employee who reported it rather than the attacker. franking unwraps to the
message being reported — recursively, so a forward of a forward still
resolves — and attributes every finding to it:

```
$ franking report.eml --findings
franking: unwrapped 'FW: is this legit?' to the message attached to it
```

Pass `--wrapper` to analyse the covering message instead.

## Install

```bash
uv tool install franking          # or: pipx install franking
```

From a clone:

```bash
git clone https://github.com/iamjoshgilman/franking
cd franking
uv tool install .                  # or: pip install -e '.[dev]'
```

## Use

```bash
franking message.eml              # interactive browser
franking message.eml --findings   # scrollback-friendly report
franking message.eml --iocs       # indicators, one per line
franking message.eml --json       # everything, machine-readable
franking message.eml --tree       # section outline
```

`--findings` exits non-zero when anything high or critical fired, so it drops
straight into a pipeline:

```bash
for f in samples/*.eml; do
  franking "$f" --findings --no-color --min-severity high || echo "FLAGGED: $f"
done
```

### Keys

There are three columns — sections, rows, and the selected row's fields —
and the cursor moves between them rightwards.

| Key | Action |
| --- | --- |
| `j` / `k` | move within the focused column |
| `l` / `→` / `⏎` | move right: sections → rows → fields |
| `h` / `←` / `⌫` | move back left |
| `tab` | cycle the three columns |
| `y` | copy the highlighted row, in whichever column has focus |
| `H` | copy the SHA-256 in context |
| `Y` | copy every row of the current section |
| `a` | copy every extracted indicator |
| `/` | search labels, values and explanations |
| `f` | jump to Findings |
| `e` | export JSON next to the file |
| `?` | help |

`y` is the one to remember, and it copies **what the focused column points
at** — put the cursor on a row's `SHA-256` field and `y` gives you the hash,
not the attachment's name. Values too wide for the field list are shown in
full in the pane above it, so a 64-character hash stays readable even when
the column clips it.

Clipboard writes go through `wl-copy`, `xclip`, `xsel`, `pbcopy` or
`clip.exe`, whichever exists, and fall back to OSC 52 so `y` still works
over SSH.

Selecting text with the mouse needs **shift+drag**. Like any TUI, franking
puts the terminal into mouse-tracking mode, so a plain drag is delivered to
the application rather than the terminal; shift bypasses that in Ghostty,
Alacritty, kitty and foot. Clicking a row also selects it, so you can click
then press `y`.

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

Rules live in `src/franking/rules/` and register themselves with a
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

franking reads files. It does not resolve DNS, fetch URLs, detonate
attachments or call out to any service, so it is safe to point at live
samples, it works offline, and no sample ever leaves the host. For an
organisation that cannot upload mail to a cloud service, that is the
point of it rather than a limitation.

What it is: an analyst's lens on **one message**, that shows its working.
What it is not: a mail security platform. It has no ingestion pipeline, no
reputation feeds and no case management, and it is not trying to replace
the gateway.

Known gaps, stated plainly so nobody discovers them the hard way:

- **No Outlook `.msg`** — only RFC 822 `.eml`.
- **No live verification.** Whether a domain's SPF record really authorises
  an address, how old the domain is, and what any reputation service thinks
  all need the network. Domain age in particular is among the strongest
  signals available, and franking cannot see it.
- **Shallow attachment analysis.** Extension chains, magic bytes and archive
  listings only. No Office macro or VBA inspection, no remote template
  injection, no PDF `/OpenAction` or `/JavaScript`, no HTML smuggling, no
  QR codes in images.
- **Weak against pure-text BEC.** The rules key on attachments and links. A
  message with neither — "are you at your desk? I need a wire sent" — scores
  low. Catching those needs a roster of who may legitimately send as whom,
  which is configuration that does not exist yet. For the same reason,
  `CONT008` only reports display-name impersonation it can prove: a brand
  name, or an address hidden inside the display name. It will not guess
  that an unfamiliar company name is a lie.
- **No team workflow.** No MISP or STIX export, no campaign clustering, no
  audit trail.

## Licence

MIT.
