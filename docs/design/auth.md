# fsgate — Authentication & Authorization Design

Status: **agreed (v1)** · Last verified against primary sources: 2026-07

fsgate is a self-hosted MCP server that Claude reaches as a custom connector over
public HTTPS. This document specifies how fsgate authenticates **the owner (you)**
and authorizes **the client (Claude)**. It is the security-critical core; read the
threat model in the top-level `README.md` first.

---

## 1. Verified facts this design rests on

These were confirmed against primary sources before committing to the design:

| # | Question | Verdict | Source |
|---|---|---|---|
| Q1 | Does `rmcp` support server-side Streamable HTTP? | **Yes** — `rmcp 2.2.0`, feature `transport-streamable-http-server`, mounts on axum as a `tower::Service` | crates.io / rust-sdk repo |
| Q2 | Does `rmcp` provide OAuth **server** helpers? | **No** — only OAuth *client* helpers (`oauth2` crate). AS/RS endpoints are hand-rolled in axum | rust-sdk `Cargo.toml` |
| Q3 | Does `fs-mcp` already do HTTP+OAuth? | **No** — stdio-only, unauthenticated, dormant. fsgate is distinct | crates.io / jbr/fs-mcp |
| Q4 | Claude connector OAuth requirements | **PKCE S256 mandatory · DCR (RFC 7591) supported (default, not strictly required) · RFC 9728 + RFC 8414 discovery · public client w/ refresh rotation** | claude.com/docs/connectors/building/authentication |
| Q4b | Does Claude **iOS** render the login page in a WebAuthn-capable browser? | **Unverified** — Anthropic does not document the native browser context. **Passkey therefore requires a fallback.** | (no primary source) |

**Consequence of Q4b:** passkey is the *preferred* owner-auth method, but a
non-WebAuthn fallback (password) must exist on the same `/authorize` page so the
owner is never locked out if Claude iOS uses a plain `WKWebView`. Passkey-only is
gated behind `FSGATE_ALLOW_PASSWORD_AUTH=false`, to be flipped once passkey login
is empirically confirmed inside the real Claude iOS connector flow.

---

## 2. Roles — who is authenticated where

OAuth has two distinct principals. Conflating them is the classic mistake.

| Principal | Authenticated at | Anchor of "it's mine" |
|---|---|---|
| **Client** (Claude) | DCR `/register` | ❌ none — `client_id` is ephemeral, cannot gate "only me" |
| **Resource owner** (you) | `/authorize` login | ✅ the passkey public key (or recovery password) provisioned out-of-band |

> The server's guarantee of "only me" is exactly as strong as the verifier the
> owner provisions before exposing the tunnel. Nothing else (client_id, tunnel
> URL, IP) is a durable identity anchor.

---

## 3. Owner identity storage — the anchor

The owner anchor is a WebAuthn **public key** (safe to store; the private key never
leaves the device's secure enclave). Persisted in a state file, not env:

`${FSGATE_STATE_DIR}/credentials.json` — perms `0600`:

```jsonc
{
  "owner_handle": "<16 random bytes, base64url — the fixed single-user id>",
  "recovery_password_hash": "argon2id$...",   // fallback + enrollment gate; NOT plaintext
  "passkeys": [
    {
      "credential_id": "base64url",
      "public_key": "COSE key bytes, base64",
      "sign_count": 42,                        // must strictly increase (clone detection)
      "transports": ["internal", "hybrid"],
      "nickname": "iPhone",
      "created_at": "RFC3339"
    }
  ],
  "oauth_clients": {                           // clients registered via DCR
    "client_xxx": { "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"] }
  },
  "token_signing_key": "<HS256 secret, generated + persisted on first run>"
}
```

**Fail-closed:** if `FSGATE_OAUTH_PASSWORD` is unset AND no passkey is enrolled, the
server refuses to issue any authorization code or token.

### WebAuthn origin binding (critical subtlety)

fsgate binds to `127.0.0.1`, but WebAuthn assertions are validated against the
**public** origin the browser saw. The server must therefore be told its public
origin explicitly:

- `FSGATE_PUBLIC_ORIGIN = https://your-machine.tailnet-xxxx.ts.net`
- `RP ID` = the registrable domain of that origin (e.g. `your-machine.tailnet-xxxx.ts.net`)

Because the passkey is bound to this RP ID, **enrollment must happen through the
public origin** (registering via `localhost` would bind the credential to RP ID
`localhost` and it would be unusable over the tunnel). If the tunnel hostname
changes, passkeys must be re-enrolled — Tailscale Funnel gives a stable hostname,
so pin to it.

---

## 4. Configuration surface

| Env var | Required | Default | Notes |
|---|---|---|---|
| `FSGATE_ROOT` | ✅ | — | Absolute path served |
| `FSGATE_PUBLIC_ORIGIN` | ✅ | — | Public HTTPS origin (WebAuthn RP + token audience) |
| `FSGATE_STATE_DIR` | ✅ | — | Where `credentials.json` lives (perms enforced) |
| `FSGATE_OAUTH_PASSWORD` | ✅* | — | Recovery/enrollment gate + fallback login. **Fail-closed if unset.** Hashed on first run |
| `FSGATE_ALLOW_PASSWORD_AUTH` | | `true` | `true`: password can complete `/authorize`. Flip to `false` for passkey-only once verified |
| `FSGATE_HOST` | | `127.0.0.1` | `0.0.0.0` only for deliberate LAN exposure |
| `FSGATE_PORT` | | `8420` | |
| `FSGATE_MCP_PATH` | | `/` | Connector interop smoothest at root |
| `FSGATE_TOKEN_SIGNING_KEY` | | generated | HS256 secret; persisted to state if generated |

\* Required until at least one passkey is enrolled; thereafter it is the fallback.

---

## 5. Endpoint map

| Endpoint | Spec | Purpose |
|---|---|---|
| `GET {MCP_PATH}` (unauth) | RFC 9728 | Returns `401 + WWW-Authenticate: Bearer resource_metadata="…"` to bootstrap discovery |
| `/.well-known/oauth-protected-resource` | RFC 9728 | `{ resource, authorization_servers: [origin] }` |
| `/.well-known/oauth-authorization-server` | RFC 8414 | Endpoint URLs + `code_challenge_methods_supported: ["S256"]` |
| `POST /register` | RFC 7591 (DCR) | Permissive: validate `redirect_uris` are https + Claude-domain, issue `client_id` (public client, no secret) |
| `GET /enroll` | — | Passkey enrollment; gated by recovery password; auto-locks once ≥1 passkey exists |
| `POST /enroll/verify` | WebAuthn `create()` | Verify attestation, store public key |
| `GET /authorize` | OAuth 2.1 | Validate client/redirect/PKCE, render login (passkey `get()` + password fallback) |
| `POST /authorize/verify` | WebAuthn `get()` | Verify assertion → issue one-time authorization code |
| `POST /token` | OAuth 2.1 | Verify code + PKCE `S256` → issue access (JWT) + refresh (rotating) |
| `{MCP_PATH}` (auth) | MCP | rmcp Streamable HTTP; Bearer middleware gates every call |

---

## 6. Flows

### 6.1 Enrollment (bootstrap the owner anchor)

```
1. Open funnel. Browser → GET /enroll  (over FSGATE_PUBLIC_ORIGIN)
2. Enter recovery password (FSGATE_OAUTH_PASSWORD)         ← gate
3. WebAuthn create():  rp{id,name}, user{handle=owner_handle},
   pubKeyCredParams[ES256 -7, RS256 -257],
   authenticatorSelection{ userVerification:"required", residentKey:"preferred" },
   attestation:"none"
4. Verify: challenge match · origin == FSGATE_PUBLIC_ORIGIN · rpIdHash match
5. Store {credential_id, public_key, sign_count} in credentials.json
6. Once ≥1 passkey exists, /enroll auto-locks (adding more requires existing
   passkey auth or password re-gate).
```

Registration is the one moment an attacker could inject *their* key and become
"you"; therefore it is password-gated, rate-limited, lockout-protected, and
self-locking.

### 6.2 Authorization (Claude connects)

```
Claude → GET /authorize?response_type=code&client_id&redirect_uri
                        &code_challenge&code_challenge_method=S256&resource&state
  ├─ client_id registered? · redirect_uri EXACT match? · PKCE present?
  ├─ render login page:
  │    primary:  WebAuthn get() (allowCredentials=stored ids, userVerification:"required")
  │    fallback: password  (only if FSGATE_ALLOW_PASSWORD_AUTH=true)
  ├─ WebAuthn verify: challenge · origin · rpIdHash · signature(public_key)
  │                   · sign_count strictly increasing · UV flag set
  └─ success → issue authorization code (short-lived, single-use,
               bound to {client_id, redirect_uri, code_challenge, resource})
           → 302 redirect_uri?code&state
```

### 6.3 Token & call

```
Claude → POST /token  { code, code_verifier, client_id, redirect_uri }
  ├─ code unused & unexpired · SHA256(code_verifier)==code_challenge
  │  · redirect_uri & client_id match
  └─ issue:
       access_token  = JWT HS256, TTL 10–15m, aud=FSGATE_PUBLIC_ORIGIN,
                        iss=origin, sub=owner_handle
       refresh_token = opaque, long-lived, ROTATED on each use, server-stored
                       (revocable)

MCP tool call → Authorization: Bearer <access>
  └─ axum middleware: verify sig · exp · aud · iss · sub==owner_handle
     else 401 + WWW-Authenticate
```

---

## 7. Hardening checklist

- [x] `credentials.json` written `0600`; refuse to start if perms are looser — `state::verify_perms`
- [x] Constant-time password comparison (Argon2id verify) — `auth::password::verify`
- [x] Lockout on password checks (`/enroll`, `/authorize/password`): 5 failures → 5 min lock — `session::Sessions`
      (`/token` is guarded by single-use codes + PKCE, not a password, so no lockout there)
- [x] `sign_count` regression → reject (cloned authenticator) — enforced by `webauthn-rs`
      (`require_valid_counter_value: true`); a regression fails `finish_passkey_authentication`
- [x] WebAuthn `userVerification: required` — `webauthn-rs` passkey ceremonies use
      `UserVerificationPolicy::Required` (registration & authentication) by default
- [x] `redirect_uri` exact-match; DCR restricts to https + Claude domains — `oauth::authorize::validate`, `oauth::dcr`
- [x] DCR state is bounded and retry-safe: identical metadata reuses a client; new registrations are capped and rate-limited — `oauth::dcr`, `session::Sessions`
- [x] Access tokens short-lived (15 min); refresh tokens rotate + are revocable (server-stored, single-use) — `oauth::token`
- [x] `aud` (RFC 8707) binds tokens to this resource — no cross-server replay — `auth::jwt`, `oauth::bearer`
- [ ] Serve only over the tunnel's TLS; never advertise a non-https origin — deployment (config enforces https origin)
- [x] Fail-closed: no verifier provisioned → no tokens, ever — `main::enforce_fail_closed`

---

## 8. Build order

1. axum skeleton · config load · `credentials.json` I/O · fail-closed guard
2. Discovery trio (RFC 9728 / 8414) + DCR `/register`
3. `/enroll` (password gate) + WebAuthn registration (`webauthn-rs`)
4. `/authorize` passkey verify + password fallback + authorization code
5. `/token` — PKCE verify · JWT access · rotating refresh
6. MCP route Bearer middleware
7. Mount rmcp Streamable HTTP + the 5 tools (`search/read/list/create/patch`)
8. Hardening pass (§7)

---

## 9. Open items to confirm empirically

- **Passkey inside Claude iOS**: complete one real passkey login through the Claude
  iOS connector flow. If it works → set `FSGATE_ALLOW_PASSWORD_AUTH=false`.
- **DCR vs CIMD**: DCR is the zero-config default; CIMD/Anthropic-held creds are
  alternatives Anthropic recommends for high-traffic servers. Single-user fsgate
  uses DCR.
