# franking

An interactive analysis lens for suspicious `.eml` files — built for CTF
and training work, where you need the right answer *and* the reason behind
it.

> A *franking mark* is the postmark that proves postage was genuinely paid.
> Forging one has been a crime since the penny post. This tool asks the same
> question of an email: are the marks it carries real, or just printed on?

Most email tooling will happily print a header block and leave you to spot
what is wrong. franking does the cross-referencing: it checks claimed
authentication results against the rest of the message, compares what a link
says against where it goes, and looks inside archives at what is actually
being delivered. Then it tells you *why* each answer matters, not just what
it is — which is the part worth keeping once the exercise is over.

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
dump. franking encodes 41 of these checks as rules, each one explaining its
own reasoning and tagged with the relevant MITRE ATT&CK technique.

## Measured, not asserted

Rules are calibrated against real mail rather than intuition, because
intuition was wrong in both directions. Current numbers over 4,400
legitimate messages (SpamAssassin ham corpus) and 4,000 real phishing
samples (Phishing Pot):

| | legitimate mail | real phishing |
| --- | --- | --- |
| produces a finding at >= medium | **2.1%** | **67.5%** |
| crashes | 0 | 0 |

Reproduce with `python tools/corpus.py ham <dir>` and
`python tools/corpus.py phish <dir>`, which report the rate per rule so
a noisy rule is visible rather than averaged away.

Measurement changed the rule set substantially. `ROUTE003` (Received
timestamps out of order) fired on 20% of legitimate mail: backwards
steps between relays turn out to have a p50 of 89 seconds, a p90 of 17
minutes and a p99 of **three hours**, so clock skew is the norm and only
an inversion larger than a day means anything. `CONT008`'s original
heuristic -- the display name shares no word with the sending domain --
fires on 81% of legitimate mail against 77% of phishing, which is worse
than a coin toss; it was replaced with checks that can be proven.
Conversely, a sender on a free cloud tenant domain
(`*.onmicrosoft.com` and friends) appears in 24% of real phishing, and
an algorithmically generated sender domain in 10%.

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
franking --rules                  # list every detection rule
```

`--findings` exits non-zero when anything high or critical fired, so it drops
straight into a pipeline:

```bash
for f in samples/*.eml; do
  franking "$f" --findings --no-color --min-severity high || echo "FLAGGED: $f"
done
```

### Working a challenge

Most email forensics exercises ask the same handful of questions — sender,
originating IP, which relay, the link domain, the attachment name, its
SHA-256, the file hidden inside it, the ATT&CK techniques. `--iocs` answers
nearly all of them in one screen:

```
$ franking email.eml --iocs
Sender            finance@business-finance.com
Reply-To          support@business-finance.com
Originating IP    45.67.89.10
Relay IP          203.0.113.25
URL               https://secure.business-finance.com/invoice/...
Domain            secure.business-finance.com
Attachment        Invoice_2025_Payment.zip
SHA-256           8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a
Archived file     invoice_document.pdf.bat
MITRE techniques  T1036.007, T1204.002, T1566, T1566.001, T1566.002, T1656
```

Open the TUI when you want to paste exact values into a form — `a` copies
that whole list, `y` copies whichever row the cursor is on, `H` grabs the
SHA-256 from anywhere. Then read the Findings section for *why*, which is
the part that carries over to the next one.

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

## Documentation

- **[docs/RULES.md](docs/RULES.md)** — all 41 rules with severity and
  ATT&CK mapping. Generated from the registry; `franking --rules` prints
  the same thing.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — architecture, how rules are
  calibrated against real corpora, signals that were measured and
  rejected, and the library gotchas that cost the most time.

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

Every rule needs a test proving it fires on a phishing fixture **and**
stays quiet on a legitimate one, then a run against the corpora before
you believe either. A rule that cannot stay quiet is noise, and noise
teaches whoever reads the output to stop reading it.

```bash
pytest
ruff check .
python tools/gen_rules_doc.py          # after adding a rule
python tools/corpus.py ham <dir>       # before believing it
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the corpora and the
calibration facts.

## Scope

franking reads files. It does not resolve DNS, fetch URLs, detonate
attachments or call out to any service, so it is safe to point at live
samples, it works offline, and no sample ever leaves the host. For an
organisation that cannot upload mail to a cloud service, that is the
point of it rather than a limitation.

It is a lens on **one message** that shows its working. It is not a mail
security platform, has no ingestion pipeline, reputation feeds or case
management, and is not trying to replace a gateway. The rules are real
rather than exercise-shaped — everything here fires on live phishing too —
but the tool is built for sitting down with a single sample.

Known gaps, so nobody finds them the hard way:

- **No Outlook `.msg`** — RFC 822 `.eml` only.
- **No live verification.** Whether a domain's SPF record really authorises
  an address, how old the domain is, what any reputation service thinks:
  all need the network. Domain age in particular is among the strongest
  signals there is, and franking cannot see it.
- **Shallow attachment analysis.** Extension chains, magic bytes and archive
  listings. No Office macro or VBA inspection, no remote template injection,
  no PDF `/OpenAction` or `/JavaScript`, no HTML smuggling, no QR codes.
- **Weak against pure-text BEC.** The rules key on attachments and links, so
  a message with neither — "are you at your desk? I need a wire sent" —
  scores low. Catching those needs a roster of who may legitimately send as
  whom, which is configuration this tool deliberately does not have. For the
  same reason `CONT008` reports only impersonation it can prove: a brand
  name, or an address hidden inside the display name. It will not guess that
  an unfamiliar company name is a lie, because guessing means accusing real
  senders.

## Licence

MIT.
