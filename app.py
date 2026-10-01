from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash
import os, re, time, uuid, logging, secrets

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ---------------- Logging & monitoring ----------------
logging.basicConfig(filename="payment_company.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("securepay")

# ---------------- In-memory data stores ----------------
users = {
    # username: {hash, role, balance}
    "customer1": {"hash": generate_password_hash("Cust#1234"), "role": "customer", "balance": 1000.0},
    "admin1":    {"hash": generate_password_hash("Adm!n#987"), "role": "admin",    "balance": 0.0},
}
cards = {}          # username -> list of tokenized cards
transactions = []   # audit ledger
api_tokens = {}     # token -> username (API auth)

ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", secrets.token_hex(16))

# ---------------- Security helpers ----------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}₹")
rate = {}  # key -> [timestamps]

def rate_limited(key, max_hits=20, window=60):
    now = time.time()
    hits = [t for t in rate.get(key, []) if now - t < window]
    rate[key] = hits
    if len(hits) >= max_hits:
        return True
    hits.append(now)
    return False

def audit(action, detail=""):
    entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
             "actor": session.get("user") or request.headers.get("X-API-Token", "?")[:8],
             "ip": request.remote_addr, "action": action, "detail": detail}
    transactions.append(entry)
    log.info("%s | %s | %s | %s", entry["actor"], entry["ip"], action, detail)

def require_login(role=None):
    u = session.get("user")
    if not u or u not in users:
        return None
    if role and users[u]["role"] != role:
        return None
    return u

def tokenize_card(number, name):
    """Mock tokenization: store only a token + last4 (PCI-style)."""
    token = "tok_" + secrets.token_hex(8)
    return {"token": token, "last4": number[-4:], "holder": name}

# ============================ UI ============================
LAYOUT = """
<!doctype html><html><head><title>SecurePay Inc.</title>
<style>body{font-family:Arial;max-width:640px;margin:40px auto;}
nav a{margin-right:12px;} input{display:block;width:100%;padding:8px;margin:6px 0;}
button{padding:8px 18px;} .msg{color:green}.err{color:red}
.box{border:1px solid #ccc;border-radius:6px;padding:10px;margin:8px 0}</style></head><body>
<nav>
  <a href="/">Home</a><a href="/portal">Customer Portal</a>
  <a href="/pay">Payments</a><a href="/admin">Admin</a><a href="/api/docs">API</a>
</nav>
{% if err %}<p class="err">{{ err }}</p>{% endif %}
{% if msg %}<p class="msg">{{ msg }}</p>{% endif %}
{{ body|safe }}
</body></html>
"""

def page(body, err=None, msg=None):
    return render_template_string(LAYOUT, body=body, err=err, msg=msg)

# ---------------- www.securepay.example ----------------
@app.route("/")
def home():
    body = """
    <h2>SecurePay Inc. — Multi-Domain Payment Platform (Prototype)</h2>
    <div class="box"><p>We operate separate, isolated applications:</p>
    <ul>
      <li><b>/</b> — public website</li>
      <li><b>/portal</b> — customer portal (auth required)</li>
      <li><b>/pay</b> — payment application (auth + card tokenization)</li>
      <li><b>/admin</b> — admin portal (admin role only)</li>
      <li><b>/api</b> — token-authenticated backend APIs</li>
    </ul>
    <p>Demo login: customer1 / Cust#1234 &nbsp;|&nbsp; admin1 / Adm!n#987</p></div>
    """
    return page(body)

# ---------------- Authentication ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page("""
            <h3>Login</h3><form method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button>Login</button></form>""")
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    key = f"login:{request.remote_addr}"
    if rate_limited(key, max_hits=5, window=60):
        audit("login_rate_limited", u)
        return page("<h3>Login</h3>", err="Too many attempts. Wait 60 seconds."), 429
    if u in users and check_password_hash(users[u]["hash"], p):
        session.clear()
        session["user"] = u
        session["role"] = users[u]["role"]
        audit("login_success", u)
        return redirect(url_for("home"))
    audit("login_failed", u)
    return page("<h3>Login</h3>", err="Invalid username or password."), 401

@app.route("/logout")
def logout():
    audit("logout", session.get("user", "?"))
    session.clear()
    return redirect(url_for("home"))

# ---------------- portal.securepay.example ----------------
@app.route("/portal")
def portal():
    u = require_login()
    if not u:
        return redirect(url_for("login"))
    user_tx = [t for t in transactions if t["actor"] == u]
    body = f"""
    <h3>Customer Portal — {u}</h3>
    <div class="box"><p>Account balance: <b>₹{users[u]['balance']:.2f}</b></p>
    <p>Registered cards: {len(cards.get(u, []))}</p>
    <p><a href="/pay">Go to Payments</a> | <a href="/logout">Logout</a></p></div>
    <div class="box"><h4>Your activity</h4>
    {''.join(f"<p>{t['ts']} — {t['action']}</p>" for t in user_tx[-10:]) or '<p>No activity yet.</p>'}</div>
    """
    return page(body)

# ---------------- pay.securepay.example ----------------
@app.route("/pay", methods=["GET", "POST"])
def pay():
    u = require_login("customer")
    if not u:
        return page("", err="Customer login required.")
    if request.method == "POST":
        number = request.form.get("card_number", "").replace(" ", "")
        name = request.form.get("holder", "").strip()
        amount = request.form.get("amount", "")
        # Input validation
        if not re.fullmatch(r"\d{13,19}", number) or not luhn_check(number):
            return page("<h3>Payments</h3>", err="Invalid card number.")
        if not name or len(name) > 50:
            return page("<h3>Payments</h3>", err="Invalid cardholder name.")
        try:
            amount = float(amount)
            assert 0 < amount <= users[u]["balance"]
        except (ValueError, AssertionError):
            return page("<h3>Payments</h3>", err="Invalid amount.")
        # Tokenize — never store the real PAN
        card = tokenize_card(number, name)
        cards.setdefault(u, []).append(card)
        users[u]["balance"] -= amount
        audit("payment", f"{u} paid ₹{amount:.2f} via {card['last4']}")
        return page(f"""
            <h3>Payments</h3>
            <div class="box"><p class="msg">Payment of ₹{amount:.2f} processed (PROTOTYPE).</p>
            <p>Card token: {card['token']} (last4: ****{card['last4']})</p></div>""",
            msg="Only a token + last4 were stored — never the full card number.")
    return page(f"""
        <h3>Payments — {u}</h3>
        <div class="box"><p>Balance: ₹{users[u]['balance']:.2f}</p>
        <form method="post">
          <input name="card_number" placeholder="Card number (demo only, e.g. 4111 1111 1111 1111)" required>
          <input name="holder" placeholder="Cardholder name" required>
          <input name="amount" placeholder="Amount (INR)" required>
          <button>Pay</button></form>
        <p><small>Cards are tokenized; the full number is never stored.</small></p></div>
        <div class="box"><h4>Your cards</h4>
        {''.join(f"<p>****{c['last4']} ({c['token']})</p>" for c in cards.get(u, [])) or '<p>No cards yet.</p>'}</div>
    """)

def luhn_check(num):
    total, alt = 0, False
    for d in reversed(num):
        n = int(d)
        if alt:
            n *= 2
            if n > 9: n -= 9
        total += n
        alt = not alt
    return total % 10 == 0

# ---------------- admin.securepay.example ----------------
@app.route("/admin")
def admin():
    u = require_login("admin")
    if not u:
        audit("admin_access_denied", session.get("user", "anonymous"))
        return page("", err="Admin access denied."), 403
    audit("admin_panel_access")
    body = f"""
    <h3>Admin Portal</h3>
    <div class="box"><h4>Users</h4>
    {''.join(f"<p><b>{k}</b> — role: {v['role']}, balance: ₹{v['balance']:.2f}</p>" for k, v in users.items())}</div>
    <div class="box"><h4>Recent audit events ({len(transactions)})</h4>
    {''.join(f"<p>{t['ts']} | {t['actor']} | {t['action']} | {t['ip']}</p>" for t in transactions[-15:])}</div>
    <div class="box"><p>Admin API key (for /api/*): <code>{ADMIN_API_KEY}</code></p></div>
    """
    return page(body)

# ---------------- api.securepay.example ----------------
@app.route("/api/docs")
def api_docs():
    return page("""
    <h3>SecurePay API</h3>
    <div class="box">
    <p><code>POST /api/token</code> — log in with JSON credentials, receive API token.</p>
    <p><code>GET /api/v1/me</code> — account info. Header: <code>X-API-Token</code>.</p>
    <p><code>GET /api/v1/transactions</code> — your transactions (customer token).</p>
    <p><code>GET /api/v1/users</code> — all users (requires admin API key header
    <code>X-Admin-Key</code>).</p>
    <p>All API routes are rate-limited (30 req/min per token) and fully audited.</p>
    </div>""")

@app.route("/api/token", methods=["POST"])
def api_token():
    if rate_limited(f"api-login:{request.remote_addr}", 5, 60):
        return jsonify({"error": "rate_limited"}), 429
    data = request.get_json(silent=True) or {}
    u, p = data.get("username", ""), data.get("password", "")
    if u in users and check_password_hash(users[u]["hash"], p):
        token = secrets.token_hex(24)
        api_tokens[token] = u
        audit("api_token_issued", u)
        return jsonify({"token": token, "role": users[u]["role"]})
    audit("api_login_failed", u)
    return jsonify({"error": "invalid_credentials"}), 401

def api_auth(admin=False):
    token = request.headers.get("X-API-Token", "")
    u = api_tokens.get(token)
    if not u:
        return None
    if admin and users[u]["role"] != "admin":
        return None
    if rate_limited(f"api:{token[:12]}", 30, 60):
        abort(429)
    return u

@app.route("/api/v1/me")
def api_me():
    u = api_auth()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"username": u, "role": users[u]["role"],
                    "balance": users[u]["balance"]})

@app.route("/api/v1/transactions")
def api_tx():
    u = api_auth()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"transactions": [t for t in transactions if t["actor"] == u]})

@app.route("/api/v1/users")
def api_users():
    if request.headers.get("X-Admin-Key") != ADMIN_API_KEY:
        audit("api_admin_key_rejected")
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"users": [{"username": k, "role": v["role"]}
                              for k, v in users.items()]})

# ---------------- Global security controls ----------------
@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    # In production behind HTTPS also add:
    # resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

@app.errorhandler(404)
def e404(e):
    return page("", err="Not found."), 404

@app.errorhandler(500)
def e500(e):
    log.error("Internal error: %s", e)
    return "Internal server error.", 500

if __name__ == "__main__":
    app.run(debug=False, port=5000)
