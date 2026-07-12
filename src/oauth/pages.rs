//! Server-rendered login/enrollment pages.
//!
//! fsgate ships no build step and no external JS: the WebAuthn ceremony is
//! driven by a small vanilla script embedded here. Because `webauthn-rs`
//! serialises challenge fields as base64url strings (not `ArrayBuffer`s), the
//! browser must convert them before calling `navigator.credentials`, and
//! convert the authenticator's `ArrayBuffer` responses back to base64url. Those
//! conversions live in `WEBAUTHN_JS`.

use askama::Template;
use axum::response::Html;

use crate::oauth::authorize::AuthorizeParams;

/// base64url <-> ArrayBuffer helpers plus response marshalling, shared by both
/// ceremonies. Kept dependency-free and CSP-friendly (no inline eval, no CDN).
const WEBAUTHN_JS: &str = r#"
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4;
  if (pad) s += '='.repeat(4 - pad);
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function decodeCreationOptions(opts) {
  const pk = opts.publicKey;
  pk.challenge = b64urlToBuf(pk.challenge);
  pk.user.id = b64urlToBuf(pk.user.id);
  if (Array.isArray(pk.excludeCredentials)) {
    for (const c of pk.excludeCredentials) c.id = b64urlToBuf(c.id);
  }
  return opts;
}
function decodeRequestOptions(opts) {
  const pk = opts.publicKey;
  pk.challenge = b64urlToBuf(pk.challenge);
  if (Array.isArray(pk.allowCredentials)) {
    for (const c of pk.allowCredentials) c.id = b64urlToBuf(c.id);
  }
  return opts;
}
function encodeAttestation(cred) {
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufToB64url(cred.response.attestationObject),
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
    },
    clientExtensionResults: {},
  };
}
function encodeAssertion(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufToB64url(r.authenticatorData),
      clientDataJSON: bufToB64url(r.clientDataJSON),
      signature: bufToB64url(r.signature),
      userHandle: r.userHandle ? bufToB64url(r.userHandle) : null,
    },
    clientExtensionResults: {},
  };
}
async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error_description || data.error || ('HTTP ' + res.status));
  return data;
}
"#;

const BASE_CSS: &str = r#"
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  margin: 0; min-height: 100dvh; display: grid; place-items: center;
  background: #0b0d12; color: #e7e9ee; padding: 24px;
}
.card {
  width: 100%; max-width: 380px; background: #151922; border: 1px solid #232936;
  border-radius: 16px; padding: 28px; box-shadow: 0 20px 60px rgba(0,0,0,.4);
}
h1 { font-size: 20px; margin: 0 0 4px; letter-spacing: -.01em; }
p.sub { margin: 0 0 20px; color: #9aa3b2; font-size: 14px; }
label { display: block; font-size: 13px; color: #9aa3b2; margin: 14px 0 6px; }
input[type=password] {
  width: 100%; padding: 11px 12px; border-radius: 10px; border: 1px solid #2b3242;
  background: #0e1117; color: #e7e9ee; font-size: 15px;
}
input:focus { outline: 2px solid #4c8bf5; border-color: transparent; }
button {
  width: 100%; margin-top: 16px; padding: 12px; border: 0; border-radius: 10px;
  background: #4c8bf5; color: #fff; font-size: 15px; font-weight: 600; cursor: pointer;
}
button:hover { background: #3d7bec; }
button:disabled { opacity: .55; cursor: default; }
button.secondary { background: #232936; color: #e7e9ee; }
button.secondary:hover { background: #2b3242; }
.divider { display: flex; align-items: center; gap: 12px; margin: 20px 0 4px; color: #5c6675; font-size: 12px; }
.divider::before, .divider::after { content: ""; flex: 1; height: 1px; background: #232936; }
.status { margin-top: 16px; font-size: 13px; min-height: 18px; }
.status.err { color: #ff6b6b; }
.status.ok { color: #51cf66; }
.hidden { display: none; }
"#;

#[derive(Template)]
#[template(
    source = r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fsgate — enroll passkey</title>
<style>{{ css|safe }}</style>
</head><body>
<main class="card">
  <h1>Enroll a passkey</h1>
  <p class="sub">One-time owner setup. Enter your recovery password, then register this device.</p>
  <label for="pw">Recovery password</label>
  <input id="pw" type="password" autocomplete="current-password" autofocus>
  <button id="go">Register passkey</button>
  <div id="status" class="status"></div>
</main>
<script>{{ webauthn_js|safe }}
const status = document.getElementById('status');
const go = document.getElementById('go');
function setStatus(msg, kind) { status.textContent = msg; status.className = 'status ' + (kind || ''); }
async function enroll() {
  const password = document.getElementById('pw').value;
  if (!password) { setStatus('Enter your recovery password.', 'err'); return; }
  go.disabled = true; setStatus('Starting…');
  try {
    const start = await postJson('/enroll/start', { password });
    setStatus('Follow your device prompt…');
    const cred = await navigator.credentials.create(decodeCreationOptions(start.options));
    await postJson('/enroll/verify', { sid: start.sid, credential: encodeAttestation(cred) });
    setStatus('Passkey enrolled. You can close this page.', 'ok');
    go.classList.add('hidden');
  } catch (e) {
    setStatus(e.message || String(e), 'err');
    go.disabled = false;
  }
}
go.addEventListener('click', enroll);
</script>
</body></html>"##,
    ext = "html"
)]
struct EnrollTemplate<'a> {
    css: &'a str,
    webauthn_js: &'a str,
}

#[derive(Template)]
#[template(
    source = r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fsgate — authorize</title>
<style>{{ css|safe }}</style>
</head><body>
<main class="card">
  <h1>Authorize access</h1>
  <p class="sub">Claude is requesting access to your files. Confirm it's you.</p>
  <button id="pkbtn">Sign in with passkey</button>
{% if allow_password %}
  <div class="divider">or</div>
  <label for="pw">Recovery password</label>
  <input id="pw" type="password" autocomplete="current-password">
  <button id="pwbtn" class="secondary">Sign in with password</button>
{% endif %}
  <div id="status" class="status"></div>
</main>
<script>{{ webauthn_js|safe }}
const OAUTH = {{ params|json|safe }};
const ALLOW_PW = {{ allow_password }};
const status = document.getElementById('status');
function setStatus(msg, kind) { status.textContent = msg; status.className = 'status ' + (kind || ''); }
function go(url) { window.location.assign(url); }
async function passkey() {
  const btn = document.getElementById('pkbtn'); btn.disabled = true; setStatus('Starting…');
  try {
    const start = await postJson('/authorize/start', OAUTH);
    setStatus('Follow your device prompt…');
    const cred = await navigator.credentials.get(decodeRequestOptions(start.options));
    const out = await postJson('/authorize/finish', { sid: start.sid, credential: encodeAssertion(cred) });
    go(out.redirect);
  } catch (e) { setStatus(e.message || String(e), 'err'); btn.disabled = false; }
}
document.getElementById('pkbtn').addEventListener('click', passkey);
if (ALLOW_PW) {
  document.getElementById('pwbtn').addEventListener('click', async () => {
    const password = document.getElementById('pw').value;
    if (!password) { setStatus('Enter your recovery password.', 'err'); return; }
    const btn = document.getElementById('pwbtn'); btn.disabled = true; setStatus('Verifying…');
    try {
      const out = await postJson('/authorize/password', Object.assign({ password }, OAUTH));
      go(out.redirect);
    } catch (e) { setStatus(e.message || String(e), 'err'); btn.disabled = false; }
  });
}
</script>
</body></html>"##,
    ext = "html"
)]
struct AuthorizeTemplate<'a> {
    css: &'a str,
    webauthn_js: &'a str,
    params: &'a AuthorizeParams,
    allow_password: bool,
}

/// The passkey enrollment page. Password-gated; auto-locks once a passkey exists.
pub fn enroll_page() -> Result<Html<String>, askama::Error> {
    EnrollTemplate {
        css: BASE_CSS,
        webauthn_js: WEBAUTHN_JS,
    }
    .render()
    .map(Html)
}

/// The `/authorize` login page. Askama's `json` filter produces JavaScript-safe
/// JSON which cannot terminate the surrounding `<script>` element.
pub fn authorize_page(
    params: &AuthorizeParams,
    allow_password: bool,
) -> Result<Html<String>, askama::Error> {
    AuthorizeTemplate {
        css: BASE_CSS,
        webauthn_js: WEBAUTHN_JS,
        params,
        allow_password,
    }
    .render()
    .map(Html)
}

#[cfg(test)]
mod xss_probe {
    use super::*;
    use crate::oauth::authorize::AuthorizeParams;

    #[test]
    fn probe_state_escaping() {
        let raw = r#"{"response_type":"code","client_id":"c","redirect_uri":"https://claude.ai/x","code_challenge":"x","code_challenge_method":"S256","state":"</script><script>alert(1)</script>"}"#;
        let params: AuthorizeParams = serde_json::from_str(raw).unwrap();
        let html = authorize_page(&params, true).unwrap().0;
        let vulnerable = html.contains("</script><script>alert(1)");
        eprintln!("VULNERABLE={vulnerable}");
        // find the OAUTH line
        for line in html.lines() {
            if line.contains("const OAUTH") {
                eprintln!("LINE: {line}");
            }
        }
        assert!(!vulnerable, "closing script tag not escaped -> XSS");
    }

    fn params() -> AuthorizeParams {
        let raw = r#"{"response_type":"code","client_id":"c","redirect_uri":"https://claude.ai/x","code_challenge":"x","code_challenge_method":"S256"}"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn enroll_page_renders_the_recovery_password_form() {
        let html = enroll_page().unwrap().0;
        assert!(html.contains("Enroll a passkey"));
        assert!(html.contains("Recovery password"));
        // The dependency-free WebAuthn helpers must be inlined into the page.
        assert!(html.contains("navigator.credentials.create"));
    }

    #[test]
    fn authorize_page_shows_the_password_option_only_when_enabled() {
        let with_pw = authorize_page(&params(), true).unwrap().0;
        assert!(with_pw.contains("Sign in with password"));
        assert!(with_pw.contains("const ALLOW_PW = true"));

        // With password auth disabled the password branch of the template is gone.
        let without_pw = authorize_page(&params(), false).unwrap().0;
        assert!(!without_pw.contains("Sign in with password"));
        assert!(without_pw.contains("const ALLOW_PW = false"));
        assert!(without_pw.contains("Sign in with passkey"));
    }
}
