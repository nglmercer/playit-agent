# Playit API Inventory (workspace coverage)

Endpoints wrapped or replayed by this workspace, verified against
`packages/api_client/src/api.rs` (35 generated routes, all `POST` JSON) and,
where noted, live against `https://api.playit.gg`.
One row per endpoint; status follows the progression
(`observed → replayed → modeled → typed → tested`).

Run `tools/api-coverage.sh` to compare the generated client and this
file. Fixtures and tests must use fake ids, emails, UUIDs, tokens, and
secrets.

## Typed and tested (mock-server)

| Path | Auth | Wrapper | Retry | Notes |
|---|---|---|---|---|
| `POST /login/signin` | anonymous | `api_client::auth::sign_in` | never (credential-bearing) | Returns `AccountSession`; live-verified 2026-09-07; TOTP-`required` ends the flow via `TotpError::NotSupported` |
| `POST /tunnels/list` | account session (`Bearer`) via `AccountSession::account_client` | `api_client::web_api::list_tunnels`, `validate_session`, `validate_with_key` | transient-safe (read-only) | Carrier replayed live 2026-09-07; validation call for `account validate` |
| `POST /domains/list` | account session (`Bearer`) | `api_client::web_api::list_domains` | transient-safe (read-only) | Replayed live 2026-09-07 (empty list) |
| `POST /v1/tunnels/list` | account session (`Bearer`) | generated client | transient-safe (read-only) | Replayed live 2026-09-07 |
| `POST /query/region` | account session (`Bearer`) | generated client | transient-safe (read-only) | Replayed live 2026-09-07 |
| `POST /shop/availability/custom_domain` | account session (`Bearer`) | generated client | transient-safe (read-only) | Replayed live 2026-09-07 (`is_available`) |
| `POST /tunnels/rename` | account session (`Bearer`) | CLI path (direct) | never (write) | Round-trip replayed live 2026-09-07 (rename → verify → restore) |
| `POST /tunnels/create` | account session (`Bearer`) | `api_client::web_api::create_tunnel` | never (creates a resource) | Full lifecycle replayed live 2026-09-07 |
| `POST /tunnels/delete` | account session (`Bearer`) | `api_client::web_api::delete_tunnel` | never (destructive) | Replayed live 2026-09-07 as lifecycle cleanup |
| `POST /claim/setup` | anonymous | CLI `claim generate` / `claim inspect` / `claim exchange` flow | caller-chosen poll budget only | Code is the capability; `WaitingForUserVisit` observed live |
| `POST /claim/exchange` | anonymous | CLI `claim exchange` flow | never (issues long-term secret) | Replayed live 2026-09-07 as the end of the browserless loop |
| `POST /claim/details` | account session (`Bearer`) | `api_client::web_api::claim_details` | transient-safe while `WaitingForAgent` | Replayed live 2026-09-07; shapes + fail map from the site bundle |
| `POST /claim/accept` | account session (`Bearer`) | `api_client::web_api::accept_claim`, CLI `claim approve` | never (creates an agent) | Replayed live 2026-09-07; fail map from the site bundle |
| `POST /claim/reject` | account session (`Bearer`) | `api_client::web_api::reject_claim`, CLI `claim reject` | never (state change) | Replayed live 2026-09-07; fail map from the site bundle |
| `POST /agents/list` | account session (`Bearer`) | `api_client::web_api::list_agents`, CLI `agents list` | transient-safe (read-only) | Replayed live 2026-09-07; dashboard extras ignored |
| `POST /agents/delete` | account session (`Bearer`) | `api_client::web_api::delete_agent`, CLI `agents delete` | never (destructive) | Replayed live 2026-09-07 (created then deleted a test agent) |
| `POST /login/totp` | pending account session (`Bearer`) | `api_client::auth::complete_totp`, CLI login prompt | never (credential-bearing) | `fail` path replayed live 2026-09-07; `success` path needs a TOTP account |

## Replayed live via the generated client

| Path | Auth | Notes |
|---|---|---|
| `POST /login/clearcookie` | token credential (no-op) | Success response but the credential survives; cookie sessions only |
| `POST /info/pops` | account session (`Bearer`) | Replayed live 2026-09-07 (22 POPs) |
| `POST /agents/routing/get` | account session (`Bearer`) | Replayed live 2026-09-07: success with an agent id; `fail MissingAgentId` without one |
| `POST /agents/rename` | account session (`Bearer`) | Round-trip replayed live 2026-09-07 (rename → verify → restore) |
| `POST /tunnels/enable` | account session (`Bearer`) | Round-trip replayed live 2026-09-07 (disable → verify → enable → verify) |
| `POST /claim/setup` | anonymous | Replayed live 2026-09-07 (`WaitingForUserVisit`) |

## Generated-model drift (verified live, needs generator refresh)

| Path | Live shape | Generated model | Action |
|---|---|---|---|
| `POST /shop/prices` | `{currency_guess, prices[]}` with `{product, currency, monthly, yearly}` items | `ShopPrices {custom_domain, dedicated_ip, …}` — does not match | No typed wrapper until the generator is refreshed; do not parse into `ShopPrices` |
| `POST /agents/rundata` | rejects `Bearer` with 401 `InvalidHeader` | `AgentRunData` | Agent-Key-only endpoint; no account wrapper. Re-verify with an agent key after a claim completes |

## Generated but not yet wrapped (read-only candidates)

These use `RetryPolicy::Transient` in the generated client and are the next
wrap candidates after a live replay with an account session:

| Path | Notes |
|---|---|
| `POST /v1/schemas/get` | Tunnel schema data |
| `POST /v1/agents/rundata` | V1 agent runtime data (likely Agent-Key, like `/agents/rundata`) |
| `POST /charge/get` | Charge details (read-only billing state; needs a reference code) |

## Generated but not yet wrapped (writes: replay on disposable resources first)

These use `RetryPolicy::Never`. Follow `docs/reverse-engineering.md` §4
before wrapping: perform once on a disposable resource and revert.

| Path | Notes |
|---|---|
| `POST /v1/tunnels/create` | V1 tunnel creation |
| `POST /v1/tunnels/config` | V1 tunnel configuration |
| `POST /v1/tunnels/propset` | V1 tunnel property set |
| `POST /tunnels/create` | Tunnel creation |
| `POST /tunnels/update` | Tunnel update |
| `POST /tunnels/delete` | Tunnel deletion (destructive) |
| `POST /tunnels/rename` | Tunnel rename |
| `POST /tunnels/firewall/assign` | Firewall assignment |
| `POST /tunnels/ratelimit` | Rate limit change |
| `POST /tunnels/enable` | Tunnel enable/disable |
| `POST /tunnels/proxy/set` | Proxy settings |
| `POST /agents/rename` | Agent rename |
| `POST /agents/routing/set` | Agent routing change (restore afterwards) |
| `POST /proto/register` | Protocol registration (secret-adjacent; retry never) |

## Observed in the site bundle, not yet replayed

Found by reading the official web client's API surface
(`playit.gg/assets/prerender-*.js`, 2026-09-07). None of these paths are
invented — but none has been replayed yet, so none is wrapped. Work them
through `docs/reverse-engineering.md` before use.

| Path | Notes |
|---|---|
| `POST /login/apply`, `POST /login/create`, `POST /login/totp_prepare` | Login/TOTP setup companions of `/login/totp` |
| `POST /agents/docker/create`, `POST /agents/key` | Agent provisioning/key companions |
| `POST /v1/tunnels/regionset`, `POST /v1/tunnels/typeset` | V1 tunnel mutations |
| `POST /v1/gateway/list`, `POST /v1/gateway/delete` | Gateway management |
| `POST /v1/invoices/list`, `POST /v1/invoices/pay`, `POST /v1/invoices/void` | Billing mutations — observation/modeling only without a safe environment |
| `POST /v1/sub/invoices`, `POST /v1/migrate-offer`, `POST /v1/setupcode/get` | Subscription/setup flows |

## Known but not wrapped (blocked or out of scope)

| Path | Reason |
|---|---|
| `POST /login/guest` | Guest flow already owned by the runtime |
| `POST /login/create/guest` | Guest flow already owned by the runtime |
| `POST /login/reset/password` | Password-reset flow; not needed by the CLI |
| `POST /login/reset/send` | Password-reset flow; not needed by the CLI |
| `POST /charge/refund` | Financial mutation; stop at observation/modeling without a safe test environment |
| Admin-only/internal routes | Out of scope unless explicitly gated |

## CLI / IPC exposure

- `playit account login|logout|status|validate` — direct session lifecycle
  (login stores only the session and prompts for TOTP when required;
  logout deletes the file).
- `playit claim generate|url|inspect|approve|reject|exchange` — full direct
  claim side; `approve` looks the code up, accepts it, and points at
  `exchange`.
- `playit agents list|delete` — direct agent management.
- `playit setup --direct [--name]` — validates the stored account session,
  approves the claim directly, exchanges it, and provisions playitd. No
  browser needed.
- Daemon IPC is unchanged: account operations run in the CLI process over
  direct HTTPS (plan option 1), so the agent secret and the account session
  never cross the IPC boundary.

## Rules for adding rows

- Never add a path from memory: verify it in the generated client or in
  observed traffic first.
- Credential-bearing and secret-issuing calls are retry `never`.
- Record the auth mode actually replayed (anonymous / Agent-Key / account
  session), not the assumed one.
- Fixtures must use fake ids, emails, tokens, and secrets.
