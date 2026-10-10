# Working on franking

Everything here was learned by getting it wrong first. The rules in this
document are not style preferences; each one exists because violating it
produced a bug that shipped.

## The one rule that matters

**A rule must fire on real phishing *and* stay silent on real legitimate
mail. Both halves get a test.**

A rule that cannot stay quiet is worse than no rule, because it teaches
whoever reads the output to stop reading it. This is not hypothetical:
an audit of an earlier version found **24 of 26 realistic legitimate
messages produced findings, three of them CRITICAL**, while four
genuinely malicious messages produced nothing at all.

Every new rule needs:

- a test that it fires, in `tests/test_rules.py` or a module-specific file
- a test that it stays quiet on ordinary mail, in `tests/test_legitimate.py`
- a run against the corpora (below) before you believe either

## Architecture

```
parse.py     extracts, never judges
rules/       judges, never parses
view.py      builds one Node tree
report.py    renders that tree (text, JSON, IOCs)
tui/app.py   renders that tree interactively
```

The separation is load-bearing. `parse.py` returning a judgement would
make it untestable in isolation; a rule doing its own parsing would make
it disagree with every other rule. `view.py` exists so the TUI and the
reports cannot show different things.

`rules/_context.py` holds shared predicates — `is_bulk`, `is_bounce`,
`is_forwarded`, `same_org`, `resembles_brand`. Most false positives come
from a rule judging a message without first asking what *kind* of
message it is. A bounce envelope differing from the From address is
forgery on personal mail and mandatory practice on a mailing list.

### Adding a rule

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

It registers itself. It appears in the TUI, all four output modes and
`franking --rules` with no further wiring.

**The `detail` text is shown to users as the explanation, so it must
describe what the code actually tested.** Several shipped rules asserted
things they never checked — one claimed "delivering the same claimed
content" while testing only that links and attachments both existed, and
another explained RFC 5737 documentation ranges while firing on RFC 1918
internal relays. A reader who checks the evidence and finds it
contradicts the prose stops trusting the whole tool.

## Measuring against real mail

Synthetic fixtures inherit the blind spots of whoever wrote them. The
`body_text` bug — every rule searching the body saw only the plain part,
so an archive password in the HTML half was invisible — survived three
audits and 235 tests because every fixture was single-part.

```bash
python tools/corpus.py ham   ~/Projects/franking-corpora/ham
python tools/corpus.py phish ~/Projects/franking-corpora/phishing_pot --limit 4000
```

Both print the hit rate per rule, so a noisy rule is visible rather than
averaged away. Current baseline:

| | legitimate | phishing |
| --- | --- | --- |
| finding at >= medium | 2.1% | 67.5% |
| crashes | 0 | 0 |

A rule's worth is its **ratio**, not its detection rate. Compute
`phish% / ham%`: above 10 is strong, 4–10 usable, below 4 is barely
better than chance and should be cut or demoted.

### Fetching the corpora

They live outside the repo so they can never be committed. The phishing
corpus contains live malicious attachments and URLs; franking never
executes or fetches anything, but do not extract them.

```bash
mkdir -p ~/Projects/franking-corpora && cd ~/Projects/franking-corpora

# ~4,400 real legitimate messages. Note: 2002-2006, which predates
# cloud mail tenancy, so it cannot validate SEND001.
for f in 20030228_easy_ham.tar.bz2 20030228_easy_ham_2.tar.bz2 \
         20030228_hard_ham.tar.bz2 20021010_hard_ham.tar.bz2; do
  curl -O "https://spamassassin.apache.org/old/publiccorpus/$f"
done
mkdir -p ham && for f in *.tar.bz2; do tar -xjf "$f" -C ham; done

# ~12,000 real phishing samples, actively maintained (2.5 GB).
git clone --depth 1 https://github.com/rf-peixoto/phishing_pot.git
```

## Signals measured and rejected

Recorded so they do not get re-proposed. Measured over 4,400 legitimate
and 3,000 phishing messages:

| Candidate | phishing | legitimate | verdict |
| --- | --- | --- | --- |
| display name shares no word with sending domain | 77% | **81%** | worse than a coin toss |
| many distinct link domains (>= 5) | 9.9% | 9.0% | no signal |
| random-looking localpart | 6.8% | 4.0% | 1.7:1, too weak |
| no List-Unsubscribe but marketing-shaped | 49% | 9.4% | 5.2:1 but far too noisy |

The first is the heuristic `CONT008` originally used. It is intuitive,
it is wrong, and it fires on every human name.

## Calibration facts

Measurements that contradict intuition, so nobody re-tightens these:

- **Received timestamps go backwards constantly.** Across 2,045 observed
  steps in legitimate mail: p50 89s, p90 17 minutes, **p99 three hours**,
  max 15.3 hours. A 120-second tolerance fired on 20% of real mail. Only
  an inversion beyond a day means anything.
- **Legacy MTAs wrote an address in the Received from-clause.** AOL's
  `mail_out` did, 112 times in the corpus. `ROUTE002` once claimed "a
  real MTA could not have written this line". It could.
- **Short brand names match everything.** Two edits on `ups` reaches
  `ucsc`. The allowance in `resembles_brand` scales with name length for
  that reason.
- **Punycode A-labels look machine-generated because they are.**
  `xn--mnchen-reisebro-zvbm` is an encoding of `münchen-reisebüro`.
  Decode before judging a name's shape.

## Gotchas that cost real time

- **Textual reserves `$panel`, `$accent`, `$text`, `$surface`** as theme
  variables. Redefining one breaks the built-in stylesheet with a
  confusing error. Ours are `$pl-` prefixed.
- **`App.tree` is taken** by Textual's DOM. The document tree is
  `doc_tree`.
- **Textual converts a Rich `Text` to its own `Content`, dropping
  `no_wrap`.** Truncate row text yourself against the measured column
  width or columns wrap and the layout breaks.
- **Never `capture_output=True` with `wl-copy`.** It forks a server to
  hold the selection, that child inherits the pipes, and the call blocks
  until timeout — so every copy silently "failed" and fell back to
  writing an OSC 52 escape into the middle of Textual's output. There is
  a regression test for this.
- **`policy.default` RFC 2047-decodes header values.** For `Received`
  that is a forgery primitive: Q-encoding turns `_` into a space and
  supplies brackets, so an attacker can write a whole fabricated hop
  inside one encoded word. Read those through `_raw_header_values`,
  which uses a `compat32` view.
- **`get_payload(decode=True)` returns `None` for `message/*`**, which
  made attached messages report 0 bytes and the MD5 of the empty string.

## Checks

```bash
pytest
ruff check .
franking --rules          # catalogue, generated from the registry
```

The catalogue is generated rather than written, because hand-maintained
documentation of 41 rules drifts within a week.
