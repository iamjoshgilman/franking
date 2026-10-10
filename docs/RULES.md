# Rule catalogue

Generated from the registry -- do not edit by hand.
Regenerate with `python tools/gen_rules_doc.py`.

41 rules. Severity drives the summary verdict and the
`--min-severity` filter; see CONTRIBUTING.md for how these are
calibrated against real mail.

## Attachments and archives (`rules/attach.py`)

| ID | Severity | Title | ATT&CK |
| --- | --- | --- | --- |
| `ATT001` | critical | Attachment uses a double extension | `T1036.007`, `T1204.002` |
| `ATT002` | critical | Archive contains an executable file | `T1566.001`, `T1204.002` |
| `ATT003` | high | Attachment type contradicts its contents | `T1036` |
| `ATT004` | critical | Executable attached directly | `T1566.001`, `T1204.002` |
| `ATT005` | info | Archive is truncated or malformed | — |
| `ATT006` | critical | Encrypted archive with the password in the message | `T1027.002`, `T1566.001` |
| `ATT007` | high | Archive contains another archive | `T1027.002`, `T1566.001` |
| `ATT008` | info | Archive format could not be inspected | — |

## SPF, DKIM, DMARC and ARC (`rules/auth.py`)

| ID | Severity | Title | ATT&CK |
| --- | --- | --- | --- |
| `AUTH001` | critical | dkim=pass claimed but no DKIM-Signature header | `T1656` |
| `AUTH002` | high | Authentication-Results has no authserv-id | `T1656` |
| `AUTH003` | high | ARC-Seal i=1 is not cv=none | `T1656` |
| `AUTH004` | high | ARC-Message-Signature carries no signature data | `T1656` |
| `AUTH005` | medium | Incomplete ARC set | `T1656` |
| `AUTH006` | medium | SPF verifier does not appear in the delivery path | `T1656` |
| `AUTH007` | low | Scan-result header not bound to any scanner | `T1656` |
| `AUTH008` | info | No authentication results present | — |
| `AUTH009` | high | Authentication passed for a domain that is not the From domain | `T1656` |
| `AUTH010` | high | DKIM-Signature is not a usable signature | `T1656` |
| `AUTH011` | high | Conflicting Authentication-Results headers | `T1656` |

## Body text and links (`rules/content.py`)

| ID | Severity | Title | ATT&CK |
| --- | --- | --- | --- |
| `CONT001` | high | Reply-To points to a different address than From | `T1566`, `T1656` |
| `CONT002` | high | Body identifier does not match the identifier in the link | `T1566.002` |
| `CONT003` | high | Link text does not match its destination | `T1566.002` |
| `CONT004` | medium | URL uses a link shortener | `T1566.002` |
| `CONT005` | medium | Urgency and consequence pressure | `T1566` |
| `CONT006` | info | Message carries both links and attachments | `T1566.001`, `T1566.002` |
| `CONT007` | info | Reserved fictional phone number | — |
| `CONT008` | high | Display name impersonates a different sender | `T1656` |
| `CONT009` | info | Malformed HTML structure | — |

## Impersonation and deception (`rules/identity.py`)

| ID | Severity | Title | ATT&CK |
| --- | --- | --- | --- |
| `IDN001` | high | Domain renders as different text than it resolves to | `T1583.001`, `T1656` |
| `IDN002` | high | Domain closely resembles a well-known one | `T1583.001`, `T1656` |
| `IDN003` | high | Invisible characters in displayed text | `T1036.002`, `T1027` |
| `IDN004` | high | Reply from a domain impersonating the conversation | `T1566.001`, `T1534` |

## Received chain and addresses (`rules/routing.py`)

| ID | Severity | Title | ATT&CK |
| --- | --- | --- | --- |
| `ROUTE001` | high | SPF-authorised IP is absent from the Received chain | `T1656` |
| `ROUTE002` | low | Received header names an email address as its source host | `T1656` |
| `ROUTE003` | medium | Received timestamps are out of order | — |
| `ROUTE004` | info | X-Originating-IP is not in the Received chain | `T1656` |
| `ROUTE005` | info | Reserved or documentation IP in the path | — |
| `ROUTE006` | medium | Return-Path does not match From | `T1656` |
| `ROUTE007` | info | X-Mailer is inconsistent with the delivery path | — |

## The sending domain itself (`rules/sender.py`)

| ID | Severity | Title | ATT&CK |
| --- | --- | --- | --- |
| `SEND001` | medium | Sender uses a free cloud tenant domain | `T1583.001`, `T1566` |
| `SEND002` | medium | Sender domain looks algorithmically generated | `T1583.001` |
