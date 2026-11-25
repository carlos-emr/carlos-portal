# The Apple key for iPhone push: operator guide

(iPhone push, piece 8. Written for whoever runs the portal that sends notices to myCarlos on iPhones.
Everything here is FAKE-data safe: no real key, team or token is written in this repository.)

## What the key is, and why it is held with care

Apple's push service (APNs) accepts a push from the portal only if it carries a short-lived **provider
token**: a signed token made with a private key from the Apple Developer account, a file named
`AuthKey_<KEYID>.p8`. The portal makes that token itself (ES256), from the file, every 45 minutes.

**The key belongs to the whole Apple team, not to one app and not to one clinic.** Anyone holding the file
can send a push to **every** app of that team (every device whose token they know), with text of their
choosing, as if it came from the publisher. Apple shows the key only once, when it is created. So:

- **The publisher's organization holds it, on the portal it runs.** A clinic running its own portal cannot
  send to myCarlos with a key it made itself (a push only reaches an app whose bundle id the key's team
  owns), and the key must not be copied to clinics. (Whether a publisher-run relay is needed for clinics that
  run their own portals is a decision for Ben and counsel, not settled here.)
- **It lives on one server only**, in a file, never in the app, the repository, an image, a backup of
  application code, a chat, a ticket or a log.

## Where the file goes

| Rule | Why |
| --- | --- |
| A regular file, **not a link**, owned by the user the portal runs as, mode **`0600`** (or `0400`) | the start-up check refuses a link and any group or other permission bit |
| **Outside the repository and outside the application directory**, for example `/etc/carlos-patient-portal/apns/AuthKey_ABC123DEFG.p8` on a directory only that user can read | a deployment that replaces the application directory must not lose or expose it |
| Not inside a container image or a code-only backup | an image is copied widely; keep it in the host's secret store or a mounted secret |
| Under 4 KiB | the check refuses anything larger; a `.p8` is about 250 bytes |

Create it by copying the downloaded file once, over a trusted channel, then removing the download:

```
install -o carlos-portal -g carlos-portal -m 0600 AuthKey_ABC123DEFG.p8 /etc/carlos-patient-portal/apns/
shred -u AuthKey_ABC123DEFG.p8      # or your platform's secure delete
```

## The settings

All are environment variables of the portal process (see `deploy/production.env.example`). They are
**off by default**; nothing is sent unless all are present.

| Variable | Value |
| --- | --- |
| `PATIENT_PORTAL_MYCARLOS_APNS_ENABLED` | `true` (also needs the myCarlos delivery, mailbox and availability switches) |
| `PATIENT_PORTAL_MYCARLOS_APNS_TEAM_ID` | the Apple team id: ten upper-case letters and digits |
| `PATIENT_PORTAL_MYCARLOS_APNS_KEY_ID` | the key id of the `.p8` (the `ABC123DEFG` in the file name): ten upper-case letters and digits |
| `PATIENT_PORTAL_MYCARLOS_APNS_KEY_PATH` | the absolute path of the file above |
| `PATIENT_PORTAL_MYCARLOS_APNS_BUNDLE_ID` | myCarlos's iOS bundle id (the `apns-topic`): `ca.carlos.mycarlos` (the identifier in myCarlos's `tauri.conf.json`) |
| `PATIENT_PORTAL_MYCARLOS_NOTICE_TOKEN_KEY` | the portal's own random key for the opaque notice token: URL-safe base64 of at least 32 random bytes, for example `python -c 'import secrets; print(secrets.token_urlsafe(32))'`. Never leaves the portal |
| `PATIENT_PORTAL_OUTBOX_ENCRYPTION_KEYRING` (or `_SECRET`) | required: the devices' Apple tokens are encrypted at rest under a key derived from it. Without a configured keyring the portal refuses to bind a token and refuses to start with push on |

The sandbox or production host is chosen **per destination** from what the phone reported when it sent its
token: a development build gets sandbox tokens, TestFlight and App Store builds get production tokens.
Nothing to configure.

## What the portal checks at start-up

With push on, the portal checks the key before it serves anything, and **refuses to start** (a fixed error
code in the log, never the path or any key bytes) when:

| Code | Meaning |
| --- | --- |
| `apns_key_missing` / `apns_key_unreadable` | the file is not there or the portal's user cannot read it |
| `apns_key_not_a_regular_file` | it is a folder or a link (the file is opened without following links, and every check is made on the open file, so nothing can be swapped in between) |
| `apns_key_wrong_owner` | the file is not owned by the user the portal runs as: `chown` it |
| `apns_key_permissions_too_open` | any group or other permission bit is set: `chmod 600` it |
| `apns_key_size` | empty or over 4 KiB |
| `apns_key_invalid` | not an unencrypted PEM PKCS#8 EC key on the P-256 curve (Apple's `.p8` is exactly that) |
| `apns_team_id_invalid`, `apns_key_id_invalid` | not ten upper-case letters and digits |
| `apns_http2_unavailable` | the HTTP/2 packages (`h2` and the `httpx2` HTTP/2 extra) are not installed (see below) |

**HTTP/2:** Apple's push service speaks HTTP/2 only. The portal sends over it with `httpx2` and its
`http2` extra (`h2`, `hpack`, `hyperframe`), a runtime dependency hash-locked in
`requirements-runtime.lock` like the others. The client keeps one connection to Apple open between pushes,
negotiates HTTP/2 only (a server that does not offer it is refused, never downgraded), follows no redirect,
retries nothing and logs nothing, and reads no proxy or certificate setting from the environment: pushes go
straight to Apple. If the packages are missing (an image built without the extra) the portal refuses to start
with push on, with the code above, rather than failing at the first push. The portal's outbound firewall
must allow HTTPS (port 443) to `api.push.apple.com`, and to `api.sandbox.push.apple.com` if development
builds are used.

## What goes to Apple

Per push: the provider token, the app's bundle id, the device's token (in the URL), and a body of two things
only: a **localization key** (the phone looks the sentence up in its own strings, in the patient's own
language) and an opaque 22-character notice token. **No text, no name, no document title, no clinic name.**
Priority 10, type alert, an expiry, and one collapse id per destination so a pile of arrivals shows one
notice. Apple therefore learns the device token, the app, the time of each push and the portal's internet
address; the portal learns the device token (new), which it stores encrypted.

## Rotating the key

Apple allows two active keys per team and you can revoke one in the Apple Developer account.

1. In the Apple Developer account, create a **new** APNs key (keep the old one active for now) and
   download its `.p8` once.
2. Install it as above on the portal server, with its own file name (a new key id in the name).
3. Change `PATIENT_PORTAL_MYCARLOS_APNS_KEY_ID` and `..._KEY_PATH` to the new key and restart the portal.
   The start-up check proves the new file before the portal serves.
4. Watch for pushes being accepted. There is no way to see content. A key or provider-token fault shows as
   Apple's `403` (`InvalidProviderToken` or `ExpiredProviderToken`): the portal then logs the class-only line
   `APNs rejected the provider token (apns_auth_rejected)`, counts it under the failure category
   `apns_auth_rejected` in its operational metrics, and signs a fresh provider token for the next push. That
   push is not retried (a 403 is permanent for the push that met it). A non-zero `apns_auth_rejected` count
   after a rotation means the new key id, team id or file is wrong, or the clock is far off.
5. **Then** revoke the old key in the Apple Developer account and securely delete the old file.
If the portal will not start on the new key, put the old values back; the old key is still active until you
revoke it.

## If the key may have leaked

Treat it as compromised the moment more than the portal's user could read it: revoke it in the Apple
Developer account **first** (all push to every app of the team then stops until the new key is in), create a
new key, install it, restart, and then find out how the file was exposed. Pushes carry no content, so the harm
of a leaked key is bounded to someone sending alerts with text of their choosing to devices whose tokens they
know; the tokens themselves are encrypted in the portal's database and are not exposed by the key.

## What Apple's answers do

| Apple says | The portal does |
| --- | --- |
| 200 | the notice is marked accepted (never "seen") |
| 410 | the token is no longer active: the destination's token is deleted |
| 400 (`BadDeviceToken`, `BadCollapseId` and the rest) | permanent for that push, **nothing is revoked** (it can also be a mistake of ours) |
| 403 (`InvalidProviderToken`, `ExpiredProviderToken`) | permanent for that push, reported as `apns_auth_rejected`, cached provider token dropped |
| 429, 5xx, no answer | retried later |

## Device tokens in the database

Tokens are stored encrypted (AES-GCM, a key derived from the outbox keyring, with the destination,
platform and environment bound in), in their own table `patient_portal_mycarlos_push_handles`. A token is
deleted when the device turns remote notices off, when its destination or device is removed, and when Apple
answers that the token is no longer active (HTTP 410). A new token replaces the old one. Rotating the outbox
keyring keeps old rows readable while the old key stays in the keyring.
