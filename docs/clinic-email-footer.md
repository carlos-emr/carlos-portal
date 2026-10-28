# Clinic footer on portal email

All portal SMTP emails carry the clinic footer administered in CARLOS: verification,
password reset, contact change, email-change confirmation and request notices,
booking prompts and updates. The portal has no editable copy of the clinic footer.
These system messages have no personal footer.

Each new SMTP preparation reads the current trusted footer. Missing configuration,
an unreachable provider, an invalid response, or unavailable durable audit storage
stops the send before SMTP connects. The one exception: sign-in/MFA verification codes
and password-reset emails go out **without** the footer while it is unavailable, so
patients can still sign in and reset a password. There is no cached footer, and
unavailable audit storage stops every send, those two included.
After preparation, that attempt retains its footer and logo despite later admin
edits. The existing outbox queues message instructions rather than prepared MIME;
each actual worker transport attempt is a new preparation.

### Why an email wasn't sent

A refused send logs one line, `Portal email not sent: clinic footer unavailable
(reason=<reason>)`, and the outbox records `clinic_footer_<reason>` as the failure
code, so it isn't mistaken for an SMTP outage. The reason is one fixed word; it never
includes the footer, a token, an address or a message.

A sign-in code or a password reset isn't refused: it goes out without the footer, and the log
line reads `Portal email sent without footer: clinic footer unavailable (reason=<reason>)`.
Its audit record names the skipped footer's reason (`footer_skipped`).

| Reason | Check first |
| --- | --- |
| `config` | The footer URL, read credential and public keyring are set in this process |
| `transport` | CARLOS is reachable over HTTPS from here (DNS, TLS, timeout) |
| `http_status` | CARLOS answers 200 `application/json` (a wrong credential gets a refusal status) |
| `response` | The reply is the signed-footer JSON and within size limits |
| `unknown_key` | The portal's public keyring holds the key CARLOS signs with |
| `signature` | The keyring entry matches that key |
| `claims` | Issuer, audience and clinic ID match this portal |
| `freshness` | Both clocks are right (the footer is valid for at most 60 seconds) |
| `content` | The saved footer in CARLOS: its HTML, text and logo |
| `audit` | The audit volume is mounted, private and writable (this stops sign-in codes and resets too) |
| `message` | The email couldn't be assembled around the footer |
| Any of the above, for a sign-in code or password reset | Not refused: it went out without the footer (`sent without footer` in the log, `footer_skipped` in the audit) |

## Configure web and worker

Deploy the CARLOS footer provider before this portal version, then save the clinic
footer in CARLOS (**Admin > Emails > Configure Email**, **Edit footer**) before the
portal sends anything. While that footer is empty, every portal email is refused,
verification codes and password resets included. The portal needs the saved footer
even when CARLOS's own emails have the clinic footer turned **Off**. Set the same
`PATIENT_PORTAL_EMAIL_FOOTER_URL`, derived read credential, public keyring, timeout
and audit-volume path in web and outbox. The worker compatibility probe includes
these settings. The URL must use HTTPS and end in `/ws/portal/email-footer`, with
no credentials, query or fragment. Certificate/hostname verification stay enabled.
For a private CA, mount its public bundle read-only in both processes and set
`PATIENT_PORTAL_EMAIL_FOOTER_CA_FILE`. Redirects and proxy-environment routing are
not used.

The worker receives **only** the derived footer-read credential and CARLOS public
keys. It never receives the full internal API bearer or a private signing key.
The derived credential works only at CARLOS's read-only footer endpoint and grants
no staff action or historical audit access.

Derive a lowercase hexadecimal HMAC-SHA256 credential privately on the CARLOS side:

```text
key = UTF-8 bytes of the canonical current CARLOS service token
message = ASCII("carlos-portal-email-footer-read-v1") + NUL
          + unsigned 8-byte big-endian byte length of UTF-8 clinic_id
          + UTF-8 clinic_id
```

Provision through private deployment files with mode `0600`. Do not put either
credential on a command line, in logs or public artifacts. The read provider accepts
only the current CARLOS credential. For rotation, pause sends, follow the existing
service-token/public-keyring cutover, provision the new derived credential in both
processes, verify the provider, and resume. An unmatched deployment refuses sends.
No root-token fallback is allowed.

## Durable footer evidence

Set Compose's `PORTAL_EMAIL_FOOTER_AUDIT_DIR` to a dedicated persistent host
directory owned by UID/GID `10001:10001` with mode `0700`. Web, outbox and preflight
mount it at `/var/lib/carlos-portal/email-footer-audit` and use the same runtime
UID. For example, the deployment operator can prepare the directory with
`install -d -m 0700 -o 10001 -g 10001 /srv/carlos-portal/email-footer-audit`.
Use a filesystem supporting exclusive creation, atomic hard-link publication and
file/directory `fsync`. Symlink paths are rejected. Production preflight probes
durable publication and removes its temporary probe.

Each attempt has an immutable prepared artifact and a separate terminal outcome,
in one folder per UTC date and hour (`<date>/<hour>/`). Each footer revision (clinic,
exact HTML/plaintext and selected logo) is stored once, as `footers/<revision>.json`.
The revision is a hash of that content, and the file is never overwritten: a different
file under the same name stops new email. An attempt's artifact names its revision,
attempt ID, time and message kind. A sign-in code or password reset sent during a footer
outage names no revision; its `footer_skipped` gives the fixed reason instead. Files are `0600`. The footer and the attempt are
durable before any SMTP connection. It contains no recipient, subject, body, live
verification/reset/change credential, or transport/signing secret. This is **not**
an outgoing MIME spool. Schema and hashes detect corruption under trusted private
storage; they do not protect against its owner/root replacing files and hashes.

| Status | Meaning |
| --- | --- |
| `prepared` | Preparation was recorded; SMTP acceptance was not recorded. |
| `accepted` | SMTP accepted the message; patient receipt is not established. |
| `failed` | This attempt was known not to be accepted. |
| `unknown` | SMTP acceptance was unconfirmed. |

A crash after SMTP acceptance but before the outcome write leaves `prepared`.
Confirmed acceptance remains successful if QUIT or outcome bookkeeping fails.
Saved content never changes with current settings. Existing outbox retry behavior
is unchanged; these artifacts do not claim exactly-once delivery.

Back up and restore the volume with clinic audit evidence. Apply the existing
retention floor (default 25 × 366 days). This change does not automatically prune
files. Each email adds two small files (a few hundred bytes); each footer revision,
with its logo (up to about 136 KB), is stored once however many emails use it. Monitor capacity: full or non-durable storage refuses new email. Keep the
volume separate from patient attachments, and include it in deployment/rollback
planning. Older portal images do not enforce this policy; a rollback must not
silently restore footerless sends.

## Administrator access

`GET /internal/carlos/email-footer-attempts` serves saved plaintext and metadata
to CARLOS. It requires the existing service bearer **and** a fresh single-use,
request-bound staff assertion with `portal.email.audit.read`. CARLOS may attest
this permission only after server-side `_admin READ`. Instance, principal and
artifact clinic must match. Patients and the worker read credential cannot use it.

Use `date=YYYY-MM-DD` (UTC today by default), `limit=1..100`, and the exclusive
`before` cursor returned as `next_before`. Results are newest first. Each hour folder
allows at most 10,000 entries (about 5,000 attempts in one UTC hour), each artifact
256 KiB, and a page 512 KiB. A full page stops without reading older hours.
Invalid/corrupt evidence is reported unavailable. A page can end early at its byte
limit with a cursor; eligible evidence is never silently dropped. The list exposes
saved plaintext, kind, clinic, revision, status/times and logo hash; full HTML and logo
bytes stay in the stored footer file. Only an attempt that went out without the footer also
has `footer_skipped` (the reason), with null plaintext, revision and logo hash. Other attempts
keep exactly the fields above, which CARLOS's reader checks; until CARLOS accepts
`footer_skipped`, it shows a day holding such an attempt as unavailable.

The CARLOS read-only caller and admin display are a separate dependency. That
display must escape saved plaintext and use native `<details>` without `open`,
keeping each footer initially collapsed. The portal API creates no patient or
development-only administrator display.

## Signed provider contract

Each read sends 32 fresh random bytes as a canonical 43-character unpadded
base64url nonce. The reply is
`{"assertion":"base64url(payload).base64url(signature)"}`. Ed25519 signs exact
UTF-8 payload bytes using the existing CARLOS keyring. Issuer is `carlos`, audience
is `carlos-patient-portal-email-footer`; payload binds the exact nonce, clinic,
known key ID, issue time and an expiry at most 60 seconds later. Issue time permits
at most five seconds of future skew.

Fields are `iss`, `aud`, `iat`, `exp`, `nonce`, `clinic_id`, `kid`, `footer_html`,
`footer_text`, `revision` and nullable `logo`. Signed Java
`EmailFooterHtml.toPlainText` output is authoritative; Python does not recreate
Jsoup normalization. HTML is limited to 10,000 UTF-16 units and plaintext to
2,000; both must be visibly nonempty. Payload is at most 256 KiB, HTTP envelope
512 KiB. Duplicate or unknown JSON fields, compression, unsafe HTML, invalid
signatures and stale replies are refused.

HTML permits `b`, `strong`, `i`, `em`, `br`, `p`, `div`, `a`; only `a.href` is
allowed, with HTTPS/mailto and no hidden/control characters. Logo fields are
`content_id`, `content_type`, padded standard `bytes_base64`, and lowercase
`sha256`. Type is PNG/JPEG, size at most 102,400 bytes. CID is 1–128 ASCII
characters matching `[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9.-]*`.
HTML and attached MIME use the exact same CID and bytes; no remote image loads.

Revision is lowercase SHA256 over five ordered byte components: UTF-8 HTML,
UTF-8 plaintext, ASCII CID, ASCII content type, raw logo. Each is prefixed by its
unsigned eight-byte big-endian byte length. Last three components are empty when
no logo exists. Signature, revision and logo hash bind the same immutable snapshot.
Socket timeout is 1–10 seconds (default five). After TLS connects, one deadline
bounds status lines, interim responses, headers, chunk framing and body reads.
The response body is also bounded. OS DNS resolution has no claimed hard
five-second deadline.
