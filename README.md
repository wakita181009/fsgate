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

- **A private VPN is not sufficient for the *connector call*.** Tailscale's normal tailnet cannot carry Claude's requests, because Anthropic's servers are not on your tailnet. You need Tailscale **Funnel** (public) or an equivalent tunnel for the actual MCP traffic. (Enrollment is different — see below.)
- **The passkey is bound to the public origin.** WebAuthn assertions are validated against `FSGATE_PUBLIC_ORIGIN`, and the passkey's RP ID is that origin's host. So you must **enroll through the `.ts.net` hostname**, not through `localhost`. Crucially, that hostname is identical whether the server is tailnet-private (`tailscale serve`) or public (`tailscale funnel`), so you can **enroll while it is still private and only then go public** — see [Setup for iPhone](#setup-for-iphone-with-tailscale). The hostname must stay stable; if it changes, re-enroll.

---

## Tools

v1 surface. Deliberately small.

| Tool | Description |
|---|---|
| `search_notes(query, limit?)` | Full-text search across the tree |
| `read_note(path)` | Return the note's full contents (raw text, frontmatter included) |
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

## Setup for iPhone (with Tailscale)

This is the intended path, and it uses one property of Tailscale that closes a
real security gap: **your `<machine>.<tailnet>.ts.net` hostname is the same
whether it is served privately (tailnet-only, via `tailscale serve`) or exposed
publicly (via `tailscale funnel`).** Because the WebAuthn passkey is bound to
that *hostname* (the RP ID), a passkey you enroll while the server is
tailnet-private stays valid after you flip it public.

So the recommended flow is **enroll privately first, then go public** — the
enrollment page is never exposed to the internet:

1. Run fsgate on an always-on machine (e.g. a Mac mini), bound to `127.0.0.1`.
2. Serve it **tailnet-only** and enroll your passkey from your own device.
3. Only once `credentials.json` holds your passkey (and enrollment has
   auto-locked), switch the same hostname to **Funnel** to make it reachable by
   Anthropic's cloud.

### Prerequisites (one-time, in the Tailscale admin console)

- **MagicDNS + HTTPS certificates** enabled for your tailnet — this is what gives
  `<machine>.<tailnet>.ts.net` a real TLS certificate (required; WebAuthn will
  not run over an untrusted origin).
- **Funnel** enabled for this machine in your ACL policy (`nodeAttrs` →
  `funnel`). Serve needs no special ACL; Funnel does.

### 1. Run fsgate

Point `FSGATE_PUBLIC_ORIGIN` at the final ts.net hostname from the start — the RP
ID is fixed here and must not change between enrollment and public exposure:

```bash
export FSGATE_ROOT="$HOME/Documents/Notes"
export FSGATE_PUBLIC_ORIGIN="https://your-machine.tailnet-xxxx.ts.net"
export FSGATE_STATE_DIR="$HOME/.local/state/fsgate"
export FSGATE_OAUTH_PASSWORD="$(openssl rand -base64 24)"
echo "$FSGATE_OAUTH_PASSWORD"   # save this — you need it once, to enroll the passkey

./target/release/fsgate   # listens on 127.0.0.1:8420
```

### 2. Serve tailnet-only, then enroll your passkey (once)

Expose the port **inside your tailnet only** — not to the public internet yet:

```bash
tailscale serve --bg 8420
# now reachable at https://your-machine.tailnet-xxxx.ts.net
# ONLY from devices on your tailnet
```

On a device that is **on your tailnet** and holds your passkey (your iPhone with
the Tailscale app, or a Mac that syncs passkeys via iCloud Keychain), open the
enrollment page at that same hostname:

```
https://your-machine.tailnet-xxxx.ts.net/enroll
```

Enter the `FSGATE_OAUTH_PASSWORD`, then follow the Face ID / Touch ID prompt. The
origin the browser reports (`https://your-machine.tailnet-xxxx.ts.net`) matches
the RP ID fsgate was configured with, so the ceremony succeeds. Enrollment
**auto-locks after the first passkey** — adding another requires a fresh owner
ceremony. Once enrolled, the password becomes a recovery fallback.

> **Why not `localhost`?** The passkey binds to the RP ID derived from
> `FSGATE_PUBLIC_ORIGIN`. Enrolling from `http://localhost:8420` reports the wrong
> origin and the registration is rejected. You must enroll from the
> `.ts.net` hostname — which is exactly why `tailscale serve` (same hostname,
> private) is used for this step.

### 3. Switch the same hostname to public Funnel

Now that your passkey is enrolled and `/enroll` is self-locked, expose the same
hostname to the public internet so Anthropic's servers can reach it:

```bash
tailscale funnel --bg 8420
# same URL, now publicly reachable: https://your-machine.tailnet-xxxx.ts.net
```

The hostname (and therefore the RP ID) is unchanged, so your enrolled passkey
keeps working. Because enrollment happened while the server was tailnet-private,
`/enroll` was **never exposed to the public internet**.

> To roll back to private, run `tailscale funnel --bg off` (or
> `tailscale serve reset`). The hostname must stay **stable** across restarts —
> the passkey is bound to it; if it changes, re-enroll.

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

Built on [`rmcp`](https://crates.io/crates/rmcp) (the official Rust MCP SDK) for the server-side Streamable HTTP transport and [`axum`](https://crates.io/crates/axum) for HTTP. The OAuth 2.1 authorization server is **hand-rolled** — `rmcp` ships only OAuth *client* helpers, so discovery (RFC 9728/8414), DCR (RFC 7591), `/authorize`, and `/token` are implemented directly. See `Cargo.toml` for the full dependency set.

Two v1 behaviors worth knowing:
- Full-text search is a dependency-free recursive scan over the tree; `tantivy` is a v2 consideration.
- `read_note` returns the file's raw text (frontmatter is not parsed out in v1); structured frontmatter is a v2 consideration.

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
