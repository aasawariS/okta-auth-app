# OktaPath

A developer education app that teaches modern authentication concepts by demonstrating them live with real Auth0 credentials. No mocks, no demo modes — every login, MFA prompt, token, and API call is real.

The project is structured as three progressive levels. Each level builds on the previous one and adds one new concept.

| Level | Concept | New routes |
|---|---|---|
| 1 | OIDC + PKCE login with Google via Auth0 | `/`, `/login`, `/callback`, `/profile`, `/logout` |
| 2 | MFA step-up + role-based access | `/stepup/begin`, `/stepup/callback`, `/secure`, `/admin` |
| 3 | Token-gated API + identity-aware AI chat | `/api-demo`, `/api/userinfo`, `/api/introspect`, `/ai`, `/ai/chat` |

Every function in `app.py` has a plain-English comment above it. The goal is for a beginner developer to read the code top to bottom and understand exactly what is happening and why.

---

## Project structure

```
oktapath-ai/
├── .gitignore
├── README.md
│
├── level1/              ← Auth0 PKCE login only
│   ├── app.py
│   ├── requirements.txt
│   ├── .env.example
│   └── templates/
│       ├── login.html
│       └── profile.html
│
├── level2/              ← Level 1 + MFA + admin role
│   ├── app.py
│   ├── requirements.txt
│   ├── .env.example
│   └── templates/
│       ├── login.html
│       ├── profile.html
│       ├── secure.html      ← gated behind MFA
│       └── admin.html       ← gated behind admin role
│
└── level3/              ← Level 2 + token-gated API + Claude AI
    ├── app.py
    ├── requirements.txt
    ├── .env.example
    └── templates/
        ├── login.html
        ├── profile.html
        ├── secure.html
        ├── admin.html
        ├── api_demo.html    ← live Auth0 API calls
        └── ai_chat.html     ← Claude with verified identity
```

Each level is fully self-contained — you can `cd` into any folder and run it independently.

---

## What each level teaches

### Level 1 — Authorization Code flow with PKCE

The OIDC handshake from scratch. The app generates a random PKCE *verifier*, hashes it into a *challenge*, and redirects the user to Auth0 with the challenge in the URL. Auth0 redirects back with a one-time code. The server exchanges the code plus the original verifier for a signed JWT. The signature is verified against Auth0's public JWKS keys before any user data is trusted.

Concepts demonstrated: redirect-based auth, state CSRF protection, PKCE proof-of-possession, JWT signature verification, RS256, JWKS rotation, ID token claims.

### Level 2 — MFA step-up and role-based access

Adds a `/secure` route that requires a second factor. The `@mfa_required` decorator inspects the `amr` (Authentication Method Reference) claim in the user's session — if `mfa` isn't in it, the user is redirected through a fresh OIDC flow with `acr_values=...multi-factor` and `max_age=0`, which forces Auth0 to challenge them with TOTP regardless of any existing SSO session. Roles are mapped from a `.env` allowlist for simplicity (in production you'd use Auth0 roles or custom claims).

Concepts demonstrated: `acr_values`, `max_age`, the `amr` claim, server-side gating decorators, fresh-token verification after MFA, simple RBAC.

### Level 3 — Token-gated API and identity-aware AI

Two new modules. The API demo page shows the user's raw access token and exposes two protected endpoints: `GET /api/userinfo` (calls Auth0's userinfo endpoint with the Bearer token) and `POST /api/introspect` (calls Auth0's token introspection endpoint to check validity). The AI chat page wires the verified Auth0 identity (name, email, role, auth methods) into Claude's system prompt, so the AI knows exactly who it's talking to without any user-typed claims.

Concepts demonstrated: Bearer token authorization, RFC 7662 token introspection, identity injection into AI prompts, why "verified by the IdP" is fundamentally different from "user said their name is X".

---

## Setup

### One-time Auth0 setup

1. Sign up at [auth0.com](https://auth0.com) (free dev tenant).
2. **Applications → Create Application → Regular Web Application**.
3. **Settings tab:**
   - Allowed Callback URLs: `http://localhost:5000/callback,http://localhost:5000/stepup/callback`
   - Allowed Logout URLs: `http://localhost:5000`
   - Save Changes
4. Copy these into your `.env`: `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`.
5. **Authentication → Social → Google → Enable** (then under your app's **Connections** tab, toggle `google-oauth2` on).
6. **Security → Multi-factor Auth → One-time Password → Enable**, then set "Require Multi-factor Auth" to either *Always* or *When requested by client*.

### Anthropic key (Level 3 only)

Get an API key at [console.anthropic.com](https://console.anthropic.com) → API Keys → Create Key. Paste into `ANTHROPIC_API_KEY` in `level3/.env`.

---

## Run a level

```
cd level1            # or level2, level3
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -r requirements.txt
copy .env.example .env    # then fill in real values
python app.py
```

Open `http://localhost:5000` in a browser. Use **localhost**, not `127.0.0.1` — the cookies are scoped to the hostname and the redirect URIs are registered against `localhost`.

For predictable demos, open in a **private/incognito window** so you start with no existing Auth0 or Google SSO sessions.

---

## Demo notes and gotchas

A handful of issues that bit during development. All have fixes already wired into the code:

- **`State mismatch`**: caused by `localhost` ↔ `127.0.0.1` hostname switching mid-flow. Stay on one hostname end-to-end.
- **`requests.exceptions.ProxyError ... 127.0.0.1:9`**: a stale Windows proxy setting was being auto-picked by `requests`. The app uses `requests.Session(trust_env=False)` to bypass any system proxy.
- **`InvalidIssuerError`**: Auth0 stamps `iss` with a trailing slash. `ISSUER` in `app.py` includes it.
- **`ImmatureSignatureError`**: clock skew between your machine and Auth0. `jwt.decode()` is called with `leeway=60` to absorb small drifts.
- **Inconsistent consent screen**: every level's `/login` route includes `prompt=consent` so the Auth0 authorization screen always appears during demos. Remove that line for production-style "approve once" UX.
- **AI says "check your ANTHROPIC_API_KEY" but the key is fine**: the JS catch block was generic. Level 3 now returns `{"error": "..."}` from the server so you see the actual exception (typically a model-name mismatch).

---

## Resetting state for a clean demo

If a half-completed flow leaves you in a tangled state (wrong account chosen, MFA enrolled but authenticator lost, etc.), reset in this order:

1. **Auth0 dashboard → User Management → Users → Delete** the test user(s). This wipes their MFA enrollments too.
2. Open a fresh **incognito/private** browser window. (Clears localhost, Auth0, and Google session cookies in one go.)
3. **Restart Flask** (`Ctrl+C`, then `python app.py`).

Then sign in fresh — Auth0 will show consent, the QR code for MFA enrollment will appear, and you're back to a known state.

---

## Security note on `.env` files

`.env` files contain real credentials and are excluded from git via `.gitignore`. The `.env.example` files in each level hold placeholder values only and are safe to commit. **Never put real client secrets or API keys in `.env.example`.** If a real secret ever lands in a committed file, rotate it immediately in the Auth0 / Anthropic dashboard.

---

## Stack

- Python 3.10+
- Flask
- PyJWT + cryptography (for RS256 signature verification)
- requests (with `trust_env=False` session for proxy hostility)
- python-dotenv
- anthropic (Level 3 only)

No frontend frameworks. No CSS libraries. All HTML templates are vanilla HTML5 with inline styles, kept readable for someone learning.
