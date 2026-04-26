import os
import secrets
import hashlib
import base64
import json
import time
import urllib.parse
from functools import wraps

# Wipe any HTTP/HTTPS proxy this shell or OS may have configured BEFORE
# we import requests. Some tools (corp VPNs, antivirus, etc.) leave
# stale proxy env vars that point at dead local ports.
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
          "ALL_PROXY", "all_proxy"):
    os.environ.pop(_k, None)
os.environ["NO_PROXY"] = "*"
os.environ["no_proxy"] = "*"

import requests
import jwt
from jwt.algorithms import RSAAlgorithm
from flask import Flask, request, session, redirect, render_template
from dotenv import load_dotenv

# Load secrets and settings from the .env file in this folder.
load_dotenv()

AUTH0_DOMAIN        = os.getenv("AUTH0_DOMAIN")
AUTH0_CLIENT_ID     = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
REDIRECT_URI        = os.getenv("REDIRECT_URI")
STEPUP_REDIRECT_URI = os.getenv("STEPUP_REDIRECT_URI")
FLASK_SECRET        = os.getenv("FLASK_SECRET")

# Comma-separated list of admin emails from .env. We split on commas
# and strip whitespace so "a@x.com, b@x.com" works the same as "a@x.com,b@x.com".
ADMIN_EMAILS = [e.strip() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()]

# Auth0 endpoints we'll talk to. The "issuer" is the base URL Auth0
# stamps inside every ID token — we check it during verification.
# Auth0 always uses a trailing slash on the issuer claim, so ours must match.
ISSUER     = f"https://{AUTH0_DOMAIN}/"
JWKS_URL   = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
AUTH_URL   = f"https://{AUTH0_DOMAIN}/authorize"
TOKEN_URL  = f"https://{AUTH0_DOMAIN}/oauth/token"
LOGOUT_URL = f"https://{AUTH0_DOMAIN}/v2/logout"

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# A reusable HTTP client for talking to Auth0.
# trust_env=False makes requests ignore any HTTP/HTTPS proxy your
# operating system has configured (env vars, Windows registry, etc.)
# so we always reach Auth0 directly.
http = requests.Session()
http.trust_env = False
http.proxies = {}
print(f"[OktaPath] HTTP client ready. trust_env={http.trust_env} proxies={http.proxies}")

# Truncates long claim values for display (e.g. issuer URLs, user pictures).
# Used by templates on values that might overflow.
app.jinja_env.filters["short"] = lambda s, n=42: (str(s)[:n] + "…") if len(str(s)) > n else str(s)


# ─────────────────────────────────────────────────────────────
# HELPERS — PKCE + token verification
# ─────────────────────────────────────────────────────────────

# Generates a random secret string (the "verifier") used in PKCE.
# We create this before the login redirect and keep it in the session.
# It proves that the login was started by us, not intercepted by someone else.
def make_verifier():
    return base64.urlsafe_b64encode(
        secrets.token_bytes(40)
    ).rstrip(b"=").decode()


# Hashes the verifier into a "challenge" that's safe to share publicly.
# Auth0 stores this challenge. Later, when we send back the original
# verifier, Auth0 hashes it and checks both match before issuing tokens.
def make_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# Exchanges the short-lived authorization code (from Auth0's redirect)
# plus our secret verifier for real tokens. Returns a dict with
# access_token, id_token, and expires_in.
def get_tokens(code, verifier, redirect_uri=None):
    response = http.post(TOKEN_URL, data={
        "grant_type":    "authorization_code",
        "client_id":     AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "redirect_uri":  redirect_uri or REDIRECT_URI,
        "code":          code,
        "code_verifier": verifier,
    })
    return response.json()


# Fetches Auth0's public keys and caches them in memory.
# These keys are used to verify that a token was genuinely
# signed by Auth0 and hasn't been tampered with.
_jwks_cache = None
def get_jwks():
    global _jwks_cache
    if not _jwks_cache:
        _jwks_cache = http.get(JWKS_URL).json()["keys"]
    return _jwks_cache


# Verifies the ID token's signature and returns the decoded user info.
# Finds the matching public key by "kid" (key ID in the token header),
# then uses PyJWT to verify signature, expiry, issuer, and audience.
def read_token(id_token):
    header = jwt.get_unverified_header(id_token)
    keys   = get_jwks()
    key    = next(k for k in keys if k["kid"] == header["kid"])
    # leeway=60 allows up to 60 seconds of clock skew between this machine
    # and Auth0's servers. Without it, a slightly-out-of-sync clock can
    # raise ImmatureSignatureError or ExpiredSignatureError on valid tokens.
    return jwt.decode(
        id_token,
        RSAAlgorithm.from_jwk(json.dumps(key)),
        algorithms=["RS256"],
        audience=AUTH0_CLIENT_ID,
        issuer=ISSUER,
        leeway=60,
    )


# ─────────────────────────────────────────────────────────────
# HELPERS — MFA + role checks (Level 2)
# ─────────────────────────────────────────────────────────────

# Checks if the current session has MFA in the amr claim.
# Auth0 sets amr to ["mfa"] (or includes "mfa") after a second factor
# is used. We read this from the session claims we stored at login.
def mfa_done():
    claims = session.get("claims", {})
    amr    = claims.get("amr", [])
    return "mfa" in amr


# Checks if the logged-in user is an admin.
# We compare their email against the ADMIN_EMAILS list in .env.
# In a real app you would use Auth0 roles or permissions instead.
def is_admin():
    email = session.get("user", {}).get("email", "")
    return email in ADMIN_EMAILS


# ─────────────────────────────────────────────────────────────
# DECORATORS (Level 2)
# ─────────────────────────────────────────────────────────────

# Protects a route so only logged-in users can access it.
# Redirects to / if there is no active session.
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper


# Protects a route so only users who completed MFA can access it.
# If MFA has not been done, saves the page they were trying to reach,
# then sends them through the step-up flow to complete a second factor.
def mfa_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not mfa_done():
            session["after_stepup"] = request.url
            return redirect("/stepup/begin")
        return f(*args, **kwargs)
    return wrapper


# Protects a route so only admin users can access it.
# Returns a plain 403 error if the user is not an admin.
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin():
            return "Access denied — admins only", 403
        return f(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────────
# ROUTES — original Level 1 (login, callback, profile, logout)
# ─────────────────────────────────────────────────────────────

# Home page. If the user is already logged in send them to their
# profile. Otherwise show the login page.
@app.route("/")
def home():
    if "user" in session:
        return redirect("/profile")
    return render_template("login.html")


# Kick off the login. Generate a PKCE verifier and a random state
# value, save both in the session, then redirect the user to Auth0's
# login page. Auth0 will show a Google login button (and others).
@app.route("/login")
def login():
    verifier = make_verifier()
    state    = secrets.token_urlsafe(16)
    session["verifier"] = verifier
    session["state"]    = state

    params = {
        "client_id":             AUTH0_CLIENT_ID,
        "response_type":         "code",
        "scope":                 "openid profile email",
        "redirect_uri":          REDIRECT_URI,
        "state":                 state,
        "code_challenge":        make_challenge(verifier),
        "code_challenge_method": "S256",
        # prompt=consent forces Auth0 to always show the "Authorize this app"
        # screen, even if the user has previously approved. This makes demos
        # reproducible. Remove this line for production-style "approve once" UX.
        "prompt":                "consent",
    }
    return redirect(AUTH_URL + "?" + urllib.parse.urlencode(params))


# Auth0 sends the user back here after they log in.
# Check the state value matches what we stored (prevents CSRF attacks).
# Then exchange the code + verifier for tokens, verify the ID token
# is genuine, and save the user's info to the session.
@app.route("/callback")
def callback():
    if request.args.get("state") != session.get("state"):
        return "State mismatch — possible CSRF", 400
    if request.args.get("error"):
        return f"Auth error: {request.args.get('error_description')}", 400

    tokens = get_tokens(request.args["code"], session.pop("verifier"))
    claims = read_token(tokens["id_token"])
    session.pop("state", None)

    session["user"] = {
        "name":    claims.get("name"),
        "email":   claims.get("email"),
        "picture": claims.get("picture"),
        "sub":     claims.get("sub"),
    }
    session["claims"] = claims
    return redirect("/profile")


# Shows the logged-in user's profile page.
# If they're not logged in, redirect to home.
@app.route("/profile")
@login_required
def profile():
    return render_template(
        "profile.html",
        user=session["user"],
        claims=session["claims"],
    )


# Logs the user out. Clears our session first, then redirects
# to Auth0's logout endpoint so the Auth0 session is also cleared.
# After Auth0 logs them out, they come back to our home page.
@app.route("/logout")
def logout():
    session.clear()
    params = {
        "client_id": AUTH0_CLIENT_ID,
        "returnTo":  "http://localhost:5000",
    }
    return redirect(LOGOUT_URL + "?" + urllib.parse.urlencode(params))


# ─────────────────────────────────────────────────────────────
# ROUTES — MFA step-up (Level 2)
# ─────────────────────────────────────────────────────────────

# Starts the MFA step-up flow.
# This works exactly like /login but adds two extra parameters:
#   acr_values=http://schemas.openid.net/pape/policies/2007/06/multi-factor
#     — tells Auth0 "I need a second factor, not just a password"
#   max_age=0
#     — tells Auth0 "do not use any cached session, challenge them now"
# The user sees an MFA prompt even though they are already logged in.
@app.route("/stepup/begin")
@login_required
def stepup_begin():
    verifier = make_verifier()
    state    = secrets.token_urlsafe(16)
    session["stepup_verifier"] = verifier
    session["stepup_state"]    = state

    params = {
        "client_id":             AUTH0_CLIENT_ID,
        "response_type":         "code",
        "scope":                 "openid profile email",
        "redirect_uri":          STEPUP_REDIRECT_URI,
        "state":                 state,
        "code_challenge":        make_challenge(verifier),
        "code_challenge_method": "S256",
        "acr_values":            "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
        "max_age":               0,
    }
    return redirect(AUTH_URL + "?" + urllib.parse.urlencode(params))


# Auth0 redirects here after the user completes MFA.
# We verify the state, exchange the code for fresh tokens,
# confirm MFA is in the amr claim, update the session with
# the new claims, and send the user to where they were going.
@app.route("/stepup/callback")
@login_required
def stepup_callback():
    if request.args.get("state") != session.get("stepup_state"):
        return "State mismatch", 400
    if request.args.get("error"):
        return f"MFA error: {request.args.get('error_description')}", 400

    tokens = get_tokens(
        request.args["code"],
        session.pop("stepup_verifier"),
        redirect_uri=STEPUP_REDIRECT_URI,
    )
    claims = read_token(tokens["id_token"])
    session.pop("stepup_state", None)

    # Check MFA actually happened — never trust the redirect alone.
    if "mfa" not in claims.get("amr", []):
        return "MFA was not completed. Check your Auth0 MFA policy.", 400

    # Update the session with fresh claims that include MFA proof.
    session["claims"]    = claims
    session["stepup_at"] = int(time.time())
    next_url = session.pop("after_stepup", "/secure")
    return redirect(next_url)


# The secure page — only reachable after MFA.
# The @mfa_required decorator checks this automatically.
# If MFA is not done it redirects to /stepup/begin first.
@app.route("/secure")
@login_required
@mfa_required
def secure():
    claims = session["claims"]
    return render_template(
        "secure.html",
        user=session["user"],
        claims=claims,
        amr=claims.get("amr", []),
        stepup_at=session.get("stepup_at"),
        is_admin=is_admin(),
    )


# ─────────────────────────────────────────────────────────────
# ROUTES — admin (Level 2)
# ─────────────────────────────────────────────────────────────

# The admin page — only reachable by users in ADMIN_EMAILS.
# Returns 403 for everyone else.
@app.route("/admin")
@login_required
@admin_required
def admin():
    return render_template(
        "admin.html",
        user=session["user"],
        claims=session["claims"],
        is_admin=True,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
