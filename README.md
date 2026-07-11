# fsgate

[![Crates.io](https://img.shields.io/crates/v/fsgate.svg)](https://crates.io/crates/fsgate)
[![codecov](https://codecov.io/gh/wakita181009/fsgate/branch/main/graph/badge.svg)](https://codecov.io/gh/wakita181009/fsgate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Remote filesystem MCP server with OAuth 2.1 + passkey — the missing HTTP counterpart to local filesystem MCP servers, built for **Claude on iPhone**.

**fsgate** exposes a directory on your machine to Claude over authenticated HTTPS, so you can read and write your notes **from the Claude iOS app** — or a laptop on hotel WiFi, or anywhere else — not just from the desktop the files live on.

The design target is concrete: register fsgate as a custom connector **from the Claude app on your iPhone**, prove it is you with a **passkey** (Face ID / Touch ID), and use your notes from your phone. Everything below is oriented around that flow.

---

## Why this exists

Anthropic's `filesystem` MCP server and every Obsidian MCP plugin share the same limitation: they are **local stdio servers**. They work when the MCP client runs on the same machine as the files.

But Claude's custom connectors don't work that way. When you add a custom connector, **Claude connects to your MCP server from Anthropic's cloud infrastructure, not from your device** — and that is true for claude.ai, Claude Desktop, and the mobile apps alike. Your server must be reachable from the public internet.

This produces a gap:

| | Transport | Auth | Reachable from mobile Claude? |
|---|---|---|---|
| Local filesystem MCP | stdio | none | ❌ |
| Obsidian MCP plugins | localhost HTTP | none/bearer | ❌ |
| Cloudflare Workers MCP servers | HTTP | OAuth | ✅ but no access to *your* filesystem |
| **fsgate** | **Streamable HTTP** | **OAuth 2.1 + PKCE + passkey** | ✅ |

fsgate fills that gap. It is the piece that lets a directory on **your** machine be a first-class Claude connector.

---

## What it does

- Serves a single directory tree over the **Streamable HTTP** MCP transport (via the official `rmcp` SDK)
- Authenticates every request with **OAuth 2.1 authorization code + PKCE (S256)**, self-hosting the full authorization server: discovery (RFC 9728 / RFC 8414), Dynamic Client Registration (RFC 7591), and a rotating-refresh-token `/token` endpoint
- Proves **you are the owner** with a **passkey** (WebAuthn / FIDO2) enrolled out-of-band, with an optional recovery-password fallback — so only *you* can complete the login Claude is redirected to
- **Fails closed**: with no passkey and no recovery password provisioned, it refuses to start and issues no tokens, ever
- Binds to `127.0.0.1` by default — it is never exposed on your LAN, only through a tunnel you explicitly open
- **Path containment**: every path is checked against `FSGATE_ROOT`; `../` traversal and symlink escape are rejected (tested)
- **Atomic writes** (write-to-temp-then-rename) so it never corrupts files that another app (Obsidian, an editor, a sync daemon) is also touching
- Full-text search across the tree

It is **not** Obsidian-specific. A vault is just a directory of `.md` files; fsgate treats it as such. It works equally on any Markdown directory.

---

## Threat model — read this before deploying

**Once you tunnel fsgate to the public internet, the OAuth layer is the only thing standing between the world and your files.** A tunnel URL is not a secret; treat it as public.

Therefore:

1. **Only the owner can log in.** Claude (the *client*) registers itself automatically via Dynamic Client Registration — that is **not** an identity. The thing that proves it is *you* is a **passkey** you enrolled ahead of time (or the recovery password). The client_id, the tunnel URL, and your IP are none of them durable identity anchors; the passkey public key is.
2. **Fail closed.** No passkey and no recovery password → the server refuses to start and issues no authorization codes or tokens. Ever. There is no "convenient" unauthenticated mode.
3. **Path containment is non-negotiable.** Every path is verified to be inside `FSGATE_ROOT`; `../` traversal and symlink escape are rejected. This is tested.
4. **Bearer token on every tool call.** No tool function is reachable without a valid, unexpired, audience-bound token.
5. **Brute-force lockout.** Repeated bad recovery-password attempts lock the password path; the passkey path is phishing- and guess-resistant by construction.
6. **No `delete` tool in v1.** Deletion from a phone, through an LLM, is an accident waiting to happen. Use git.
7. **Scope is one directory.** fsgate serves `FSGATE_ROOT` and nothing above it.

If you are exposing a notes directory, you are exposing your thinking. Act accordingly.

---

## Architecture

```
Claude app on iPhone  (Face ID / Touch ID → passkey)
        │
        ▼
Anthropic cloud infrastructure          ← the connector call originates HERE
        │
        ▼
Public HTTPS  (Tailscale Funnel or Cloudflare Tunnel)   ← FSGATE_PUBLIC_ORIGIN
        │
        ▼
127.0.0.1:8420  ─── fsgate ───►  FSGATE_ROOT/
                    │              ├── notes/*.md
                    │              └── ...
                    ├── OAuth 2.1 AS + RS (discovery · DCR · /token)
                    ├── WebAuthn passkey login (+ password fallback)
                    ├── path containment
                    └── atomic writes
                              │
                              ▼
                    FSGATE_STATE_DIR/credentials.json  (0600)
                    passkey public keys · signing key · registered clients
```

Two things about this diagram matter:

- **A private VPN is not sufficient.** Tailscale's normal tailnet cannot work here, because Anthropic's servers are not on your tailnet. You need Tailscale **Funnel** (public) or an equivalent tunnel.
- **The passkey is bound to the public origin.** WebAuthn assertions are validated against `FSGATE_PUBLIC_ORIGIN`, and the passkey's RP ID is that origin's host. So you must **enroll the passkey through the tunnel URL**, not through `localhost`, and the tunnel hostname must be stable (Tailscale Funnel gives you one). If the hostname changes, re-enroll.

---

## Tools

v1 surface. Deliberately small.

| Tool | Description |
|---|---|
| `search_notes(query, limit?)` | Full-text search across the tree |
| `read_note(path)` | Return frontmatter + body |
| `list_notes(prefix?)` | List files under a prefix |
| `create_note(path, content)` | Create a new file (fails if it exists) |
| `patch_note(path, old_str, new_str)` | Targeted replacement; fails safely if the file changes concurrently |

`patch_note` rather than `write_note` is intentional: a full overwrite driven by an LLM on a phone, against a file it only partially read, is how you lose work.

**Deferred to later versions:** `delete_note`, `move_note` (renaming breaks `[[wikilinks]]` at the OS level, since the notes app never learns the rename happened), semantic search.

---

## Configuration

| Env var | Required | Default | Notes |
|---|---|---|---|
| `FSGATE_ROOT` | ✅ | — | Absolute path to the directory to serve (must exist) |
| `FSGATE_PUBLIC_ORIGIN` | ✅ | — | Public HTTPS origin (the tunnel URL). Used as the WebAuthn RP, the token audience, and the base for advertised endpoints. **Must be `https://`** |
| `FSGATE_STATE_DIR` | ✅ | — | Where `credentials.json` lives (passkeys, signing key, clients). Perms are enforced to `0600` |
| `FSGATE_OAUTH_PASSWORD` | ✅ \* | — | Recovery / enrollment-gate password. Hashed (Argon2id) on first run. **Fail-closed if unset and no passkey is enrolled.** Generate a strong one |
| `FSGATE_ALLOW_PASSWORD_AUTH` | | `true` | `true`: the password can complete `/authorize` as a fallback. Flip to `false` for **passkey-only** once you've confirmed passkey login works from the iOS app |
| `FSGATE_TOKEN_SIGNING_KEY` | | generated | HS256 secret for access tokens. If unset, a random key is generated and persisted to `credentials.json` |
| `FSGATE_HOST` | | `127.0.0.1` | Set to `0.0.0.0` only if you deliberately want LAN exposure |
| `FSGATE_PORT` | | `8420` | |
| `FSGATE_MCP_PATH` | | `/` | Connector interop is smoothest at the root path |

\* Required until at least one passkey is enrolled; thereafter it is the fallback and can be removed if `FSGATE_ALLOW_PASSWORD_AUTH=false`.

---

## Installation

fsgate ships as a single static binary — no runtime, no venv, no Node.

### Build from source

Requires a recent stable Rust toolchain (edition 2024, rustc ≥ 1.85). OpenSSL is
vendored and built statically, so you do **not** need a system OpenSSL.

```bash
git clone https://github.com/wakita181009/fsgate
cd fsgate
cargo build --release
# binary at ./target/release/fsgate
```

## Setup for iPhone

This is the intended path: run fsgate on an always-on machine at home, expose it
through a stable public HTTPS hostname, enroll a passkey, then add it in the
Claude iOS app.

### 1. Open a stable public tunnel

Tailscale Funnel is free on the Personal plan and gives a stable hostname:

```bash
tailscale funnel --bg 8420
# → https://your-machine.tailnet-xxxx.ts.net
```

Whatever tunnel you use, **the hostname must be stable** — the passkey is bound
to it.

### 2. Run fsgate

Point `FSGATE_PUBLIC_ORIGIN` at that exact tunnel URL:

```bash
export FSGATE_ROOT="$HOME/Documents/Notes"
export FSGATE_PUBLIC_ORIGIN="https://your-machine.tailnet-xxxx.ts.net"
export FSGATE_STATE_DIR="$HOME/.local/state/fsgate"
export FSGATE_OAUTH_PASSWORD="$(openssl rand -base64 24)"
echo "$FSGATE_OAUTH_PASSWORD"   # save this — you need it once, to enroll the passkey

./target/release/fsgate
```

### 3. Enroll your passkey (once)

Open the enrollment page **through the tunnel URL** — this is what binds the
passkey to the right origin. On the device that holds your passkey (e.g. your
iPhone, or a Mac that syncs passkeys via iCloud Keychain):

```
https://your-machine.tailnet-xxxx.ts.net/enroll
```

Enter the `FSGATE_OAUTH_PASSWORD`, then follow the Face ID / Touch ID prompt.
Enrollment **auto-locks after the first passkey** — adding another requires a
fresh owner ceremony. Once enrolled, the password becomes a recovery fallback.

### 4. Add the connector in the Claude iOS app

In the Claude app: **Settings → Connectors → Add custom connector** → paste your
`FSGATE_PUBLIC_ORIGIN`. Claude registers itself automatically (DCR) and redirects
you to fsgate's own `/authorize` page, where you confirm with your **passkey**.
After that, your notes tools are available in chats on your phone.

> **Passkey-only.** Once you've confirmed passkey login works end-to-end from the
> iOS app, set `FSGATE_ALLOW_PASSWORD_AUTH=false` and restart. From then on, only
> the passkey can authorize — the password remains solely as an out-of-band
> recovery/enrollment gate.

---

## Deployment: always-on

fsgate is only useful if it is *up*. A server that sleeps when you close your laptop lid is a server you cannot reach from your phone — which is the entire point.

On macOS:

```bash
sudo pmset -a sleep 0 disksleep 0 autorestart 1
```

Run fsgate under **launchd** so it survives reboots and power cuts. A sample plist lives in `deploy/`.

If `FSGATE_ROOT` is inside iCloud Drive, you **must** mark the folder "Keep Downloaded" in Finder. iCloud's on-demand eviction will otherwise dematerialize files and fsgate will not be able to read them.

---

## Implementation notes

**Language: Rust.**

Rationale: a single static binary with no runtime dependency is the right shape for something that must stay up for months on a headless machine. No Node version drift, no venv, no `uv`. `scp` the binary, point launchd at it, done. Fewer moving parts is not an aesthetic preference here; it is the reliability argument.

Stack:
- [`rmcp`](https://crates.io/crates/rmcp) — official Rust MCP SDK; provides the server-side **Streamable HTTP** transport, mounted as a `tower` service on axum
- [`axum`](https://crates.io/crates/axum) — HTTP framework for the OAuth/WebAuthn endpoints
- **OAuth 2.1 authorization server, hand-rolled** — `rmcp` ships only OAuth *client* helpers, so the server side (discovery RFC 9728/8414, DCR RFC 7591, `/authorize`, `/token`) is implemented directly in axum
- [`webauthn-rs`](https://crates.io/crates/webauthn-rs) — passkey (WebAuthn / FIDO2) relying-party: registration and assertion, with sign-counter clone detection and `userVerification: required`
- [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) — HS256 access tokens (pure-Rust backend, no native crypto dep)
- [`argon2`](https://crates.io/crates/argon2) — Argon2id hashing for the recovery password
- [`serde_norway`](https://crates.io/crates/serde_norway) — YAML frontmatter (the maintained successor to the deprecated `serde_yaml`)
- Full-text search is currently a dependency-free recursive scan over the tree; `tantivy` is a v2 consideration.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 authorization-server metadata (`S256` only) |
| `POST /register` | RFC 7591 Dynamic Client Registration (Claude domains only; deduplicated, bounded, rate-limited) |
| `GET /enroll` · `POST /enroll/{start,verify}` | Passkey enrollment (password-gated, self-locking) |
| `GET /authorize` · `POST /authorize/{start,finish,password}` | Owner login → authorization code |
| `POST /token` | Code + PKCE → JWT access token + rotating refresh token |
| `{FSGATE_MCP_PATH}` | MCP Streamable HTTP; Bearer-gated |

### Design resolved

The three pre-implementation open questions have been answered:

1. **`rmcp` supports server-side Streamable HTTP** (`transport-streamable-http-server`), so v1 is Rust as intended — no TypeScript detour needed.
2. **`fs-mcp` is stdio-only and unauthenticated**, so fsgate is a distinct project rather than a PR to it.
3. **MCP's OAuth profile does use Dynamic Client Registration**; fsgate implements RFC 7591 directly.

See [`docs/design/auth.md`](docs/design/auth.md) for the full authentication/authorization design and hardening checklist.

---

## Roadmap

**v1 — the gap-filler.** Streamable HTTP + OAuth + the five tools above. Nothing more. Ship it, use it for two weeks, find out whether reading your notes from a phone is actually worth anything.

**v2 — context selection.** This is where the real value is, and it is the part nobody has built. A remote file server is a commodity; *choosing what to send* is not. Vector search over the tree, plus the link graph, to return **the fragments relevant to a question at the right granularity** — rather than making the model page through files. Embedding + retrieval + link-graph traversal, all local, no third-party inference.

The honest framing: **v1 is table stakes and someone else has already built one. v2 is the only part with a defensible reason to exist.**

---

## Prior art

- `jimprosser/obsidian-web-mcp` — the closest existing thing, and the only project found that solves the same problem (remote HTTPS + OAuth + a local vault). Python. Obsidian-framed. Read its auth path before rolling your own.
- Anthropic's local `filesystem` MCP server — stdio, no auth, desktop-only.
- Obsidian MCP plugins (`Vault as MCP`, `obsidian-claude-code-mcp`, MCPVault) — all localhost, all desktop-only. `Vault as MCP` states outright that it will not run on mobile.

---

## License

Licensed under the [MIT License](LICENSE).
