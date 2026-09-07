# Playit API Reverse-Engineering Procedure

How to turn an unknown dashboard/account page or action into a typed,
tested `playit-api-client` endpoint — without breaking the account, leaking
secrets, or automating destructive actions.

This is the development-only workflow behind `docs/api-inventory.md`.
Production code must never invent endpoint paths: a route is implemented
only after it has been **observed** in official traffic and **replayed**
directly (see `docs/auth-flow.md` for the worked example: `POST
/login/signin` + `Authorization: Bearer <session_key>`).

## 0. Prerequisites

- A disposable, self-owned test account. Never use another user's account.
- A disposable agent/tunnel where the action under study is a write.
- A fresh browser profile used only for this capture.
- The recorder restricted to Playit origins (`playit.gg`, `api.playit.gg`).
- Knowledge of the current endpoint inventory (`docs/api-inventory.md`) so
  known routes are not re-captured.

## 1. Establish a sanitized baseline

1. Start the recorder **before** logging in.
2. Record only Playit origins; drop third-party analytics/CDN traffic.
3. Keep, per request: method, path, request JSON **shape**, response JSON
   **shape**, HTTP status, header **names**, cookie **names**.
4. Redact values for: passwords, TOTP codes, `Authorization`, `Cookie` /
   `Set-Cookie`, session keys, agent secrets, CSRF tokens, and emails
   unless an email is structurally significant (then use a fake one).
5. If an auth value must be inspected to understand the protocol, keep it in
   memory or in an explicitly secret local capture that is **never
   committed** (see `.gitignore`: probe profiles, HAR files, captures).

## 2. Login

- Capture the request path/method/body shape for password sign-in.
- Capture the response shape (`WebSession` / `TotpStatus` states).
- Capture cookie names and the auth header scheme actually sent by
  follow-up calls (the account API uses
  `Authorization: Bearer <session_key>` and sets no cookies).
- With a TOTP-enabled test account, capture the submit call: path, body
  (code field name), success response, and invalid-code response. This is
  the missing piece for `auth::complete_totp`, which currently returns
  `TotpError::NotSupported`.

## 3. Navigate only

- Crawl same-origin account links (`/account/...`), visiting each page
  once and waiting for network idle.
- Record the API calls each page load makes.
- Do **not** click controls whose effect is not clearly read-only:
  delete, refund, purchase, upgrade/downgrade, subscription cancel,
  account deletion, password/security reset, agent/tunnel deletion, claim
  approval/rejection.

## 4. Manual action catalog

For each button/form:

1. Classify it as read, idempotent-write, or destructive-write.
2. If it is safe, perform it once on a disposable resource
   (e.g. create a tunnel with a test prefix, verify, then delete it;
   rename a disposable agent; restore routing afterwards).
3. Record request/response and revert the state.
4. For irreversible, financial, or security-sensitive endpoints (refund,
   subscription change/cancel, account deletion, email/password/security
   changes): stop at observation/modeling unless a safe test environment
   or an explicit manual test is available.

## 5. Direct replay

Reproduce the request with `playit-api-client` using a captured account
session (`AccountSession::account_client` or `PlayitApiBuilder::bearer`).
A request counts as understood only after direct replay succeeds without
browser JavaScript. Confirm which auth the route accepts (anonymous /
Agent-Key / account session) and record it in the inventory.

## 6. Typed model

1. Replace raw JSON with typed Rust models and explicit error variants.
2. Assign the auth policy (`AuthPolicy`) and retry policy:
   credential-bearing and secret-issuing calls are retry-`never`;
   read-only calls may be transient-retry.
3. Put stable account/dashboard wrappers in
   `packages/api_client/src/web_api.rs`, keeping `api.rs` (generated)
   untouched.

## 7. Fixture and documentation

1. Sanitize the request/response (fake ids, emails, UUIDs, tokens) and add
   it as a mock-server test, following the existing tests in `auth.rs` /
   `web_api.rs` / `http_client.rs`.
2. Add one row per endpoint to `docs/api-inventory.md` with status
   (`observed → replayed → modeled → typed → tested`), auth, retry, and
   IPC/CLI exposure.
3. Run `tools/api-coverage.sh` and triage any untriaged observed endpoint.

## Open captures needed

- **TOTP submit `success` path**: `POST /login/totp` and its `fail`
  variants (`InvalidCode`, `TotpNotSetup`) are confirmed from the site
  bundle and the `fail` path was replayed live 2026-09-07. Still needs a
  TOTP-enabled test account to confirm the success session shape.
- **Bundle-observed endpoints** listed in `docs/api-inventory.md`
  (`/login/apply`, `/agents/key`, `/v1/gateway/*`, …): replay each
  directly before wrapping.
- **Claim page traffic** (optional now): the approve/reject/details calls
  were recovered from the site's app bundle and replayed live, so a
  browser capture is only needed if a future site change breaks the
  replay.
