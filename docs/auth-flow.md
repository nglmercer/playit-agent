# Playit Direct Auth — Verified Flow and Open Questions

Direct email/password login for playit.gg, as implemented in
`packages/api_client/src/auth.rs` and exposed via
`playit account login/logout/status`.

> Evidence below was verified live against `https://api.playit.gg` on
> 2026-09-07 with a disposable test account, and against the generated
> client in `packages/api_client/src/api.rs`.

## Verified: `POST /login/signin`

- Request: `LoginCredentials { email, password }` as JSON POST body.
- Envelope: `{"status":"success","data":…}` /
  `{"status":"fail","data":…}` / `{"status":"error","data":…}`.
- Success returns `WebSession { session_key, auth: WebAuthToken }`.
- Fail variants: `IncorrectCredentials`, `AccountBanned`.
- `WebAuthToken` carries `account_id`, `account_status`
  (`guest` / `email-not-verified` / `verified`), `totp_status`, `read_only`.
- `TotpStatus`: `required` / `not-setup` / `signed`.
- Base URL default: `https://api.playit.gg` (overridable via `API_BASE`).
- Fail/error envelopes arrive with 4xx statuses (observed: 400 with
  `IncorrectCredentials`, 401 with `AuthRequired`). The transport parses
  response bodies regardless of status, so typed error mapping is unaffected.

## Answered: session carrier is `Authorization: Bearer <session_key>`

Observed live with a disposable test account:

- `POST /login/signin` returns **no `Set-Cookie` header** — the API itself
  never sets cookies.
- `POST /tunnels/list` without auth → `AuthRequired`.
- Same call with a raw key in `Authorization` → `AuthRequired`.
- Same call with `Authorization: Bearer <session_key>` → success with the
  account's real tunnel list.
- `AccountSession::account_client` builds the typed client using this
  carrier.

## Answered: `/login/clearcookie` does not end token-based login

`POST /login/clearcookie` called with the Bearer credential returns success,
but the same credential still authenticates `/tunnels/list` afterwards. It
clears browser cookie state only. For token-based login, logout is
client-side discard: `playit account logout` (delete the stored file) is the
complete operation. No server-side invalidation endpoint is known.

## TOTP submit: `POST /login/totp`

Reverse-engineered from the official site's app bundle (which calls
`login_totp({code})`): `POST /login/totp` with `{code: "<6-digit>"}` on the
pending session. Fail variants from the site's error map: `InvalidCode`,
`TotpNotSetup`. The `fail` path was replayed live 2026-09-07
(`TotpNotSetup` on the non-TOTP test account); the `success` path still
needs a TOTP-enabled test account to confirm the session shape.
`auth::complete_totp` implements it, and `playit account login` prompts
for the code when the session reports `totp_status == required`.

## Validated live: full browserless claim

`POST /claim/setup` with a fresh random code returns
`WaitingForUserVisit`, matching the generated `ClaimSetupResponse` model.
The account side is three more observed endpoints (all replayed live
2026-09-07 with the test account, shapes confirmed against the site's app
bundle — no browser involved):

- `POST /claim/details {code}` → `{name, agent_type, remote_ip, version}`;
  `fail WaitingForAgent` until the machine has polled `/claim/setup`.
- `POST /claim/accept {code, name, agent_type}` → `{agent_id}`; fail
  variants from the site's error map (`InvalidCode`, `AgentNotReady`,
  `CodeNotFound`, `InvalidAgentType`, `ClaimAlreadyAccepted`,
  `ClaimRejected`, `CodeExpired`, `InvalidName`).
- `POST /claim/reject {code}` → success; afterwards details fails with
  `AlreadyRejected` and setup reports `UserRejected`.

Full loop proven live: login → setup → details → accept → setup
(`UserAccepted`) → exchange (secret issued) → the new agent appears in
`POST /agents/list`. `playit setup --direct` runs exactly this loop.

## Validated live: agents

- `POST /agents/list {}` → `{agents: [{id, name, …}]}` (dashboard extras
  ignored by the parser).
- `POST /agents/delete {agent_id, tunnels_strategy: {type:
  "move_to_agent", details: {agent_id, disable_tunnels}}}` → success
  (live-verified by creating then deleting a test agent).

## Implemented here

- `packages/api_client/src/http_client.rs` — structured `AuthState`
  (`Anonymous` / `AgentKey` / `Bearer`) with redacted `Debug`, `AuthPolicy`
  (`Anonymous` / `Agent` / `Account` / `AgentOrAccount`), `auth_kind` for
  log-safe tracing, and dynamic `set_auth`. `HttpClient::Debug` is redacted.
- `packages/api_client/src/lib.rs` — `PlayitApiBuilder`
  (`new` / `auth` / `agent_key` / `bearer` / `build`); `PlayitApi::create`
  stays as the agent-key compatibility helper.
- `packages/api_client/src/auth.rs` — `sign_in`, `AccountSession` (redacted
  `Debug`, `requires_totp`, `account_status`, `age`, `auth_state`,
  `account_client`, `validate`), `complete_totp` (`POST /login/totp`;
  success path awaits a TOTP-enabled test account).
- `packages/api_client/src/web_api.rs` — typed account wrappers
  (`validate_session`, `validate_with_key`, `list_tunnels`,
  `list_domains`, `claim_details`, `accept_claim`, `reject_claim`,
  `list_agents`, `delete_agent`, `create_tunnel`, `delete_tunnel`) with
  `WebApiError` (`SessionExpired` mapping); account-session expiry never
  implies agent secret invalidity. (`agents_rundata` is Agent-Key-only and
  `ShopPrices` has drifted from the live `/shop/prices` shape — see
  `docs/api-inventory.md`; neither is wrapped.)
- `packages/api_client/src/session.rs` — `SessionStore` trait with
  `MemorySessionStore` (ephemeral) and `FileSessionStore` (JSON at a chosen
  path, owner-only Unix permissions, unencrypted).
- `playit account login|status|logout|validate` — headless session CLI
  storing the session under the per-user config directory (login prompts
  for TOTP when required).
- `playit claim inspect|approve|reject|exchange` — full direct claim side.
- `playit agents list|delete` — direct agent management.
- `playit setup --direct [--name]` — validates the stored account session,
  approves the claim directly, exchanges it, and provisions playitd. No
  browser needed.
- Unit tests use a local mock HTTP server; no live credentials anywhere.
  One env-gated `#[ignore]` live test (`live_signin_and_validate`) mirrors
  the manual verification and never runs in CI.
- `packages/api_client/tests/live_e2e.rs` — end-to-end tests that run only
  when a gitignored `.env` provides `PLAYIT_TEST_EMAIL` +
  `PLAYIT_TEST_PASSWORD` (otherwise they pass with a skip notice):
  sign-in/validate/reads, claim-setup wait state, plus self-restoring
  mutation round-trips (rename needs `PLAYIT_TEST_TUNNEL_ID`, lifecycle
  needs `PLAYIT_TEST_AGENT_ID`).

## Security rules for this area

- Never log password, TOTP code, `session_key`, cookie values, or the
  `Authorization` header value.
- `Debug` impls on session types must stay redacted (covered by tests).
- No credential or session persistence beyond the explicit session file.
