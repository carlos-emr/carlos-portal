# Clinic footer on portal email

All portal SMTP emails carry the clinic footer administered in CARLOS: verification,
password reset, contact change, email-change confirmation and request notices,
booking prompts and updates. The portal has no editable copy of the clinic footer.
These system messages have no personal footer.

Each new SMTP preparation reads the current trusted footer. Missing configuration,
an unreachable provider, an invalid response, or unavailable durable audit storage
stops the send before SMTP connects. There is no cached or footerless fallback.
After preparation, that attempt retains its footer and logo despite later admin
edits. The existing outbox queues message instructions rather than prepared MIME;
each actual worker transport attempt is a new preparation.

## Configure web and worker

Deploy the CARLOS footer provider before this portal version. Set the same
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
partitioned by UTC date. Files are `0600`. Preparation is durable before any SMTP
connection. Evidence includes clinic/revision, exact HTML/plaintext, selected logo,
attempt ID, time and message kind. It contains no recipient, subject, body, live
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
files. Monitor capacity: full or non-durable storage refuses new email. Keep the
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
`before` cursor returned as `next_before`. Results are newest first. A directory
scan allows at most 10,000 entries, each artifact 256 KiB, and a page 512 KiB.
Invalid/corrupt evidence is reported unavailable. A page can end early at its byte
limit with a cursor; eligible evidence is never silently dropped. The list exposes
saved plaintext, kind, clinic, revision, status/times and logo hash; full HTML and
logo bytes stay in the artifact.

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
