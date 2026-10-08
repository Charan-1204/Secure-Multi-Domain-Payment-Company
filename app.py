from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash
import os, re, time, uuid, logging, secrets

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ---------------- Logging & monitoring ----------------
logging.basicConfig(
    filename="payment_company.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("securepay")

# ---------------- In-memory data stores ----------------
users = {
    "customer1": {"hash": generate_password_hash("Cust#1234"), "role": "customer", "balance": 1000.0},
    "admin1": {"hash": generate_password_hash("Adm!n#987"), "role": "admin", "balance": 0.0},
}
cards = {}
transactions = []
api_tokens = {}
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", secrets.token_hex(16))

# ---------------- Security helpers ----------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
rate = {}


def rate_limited(key, max_hits=20, window=60):
    now = time.time()
    hits = [t for t in rate.get(key, []) if now - t < window]
    rate[key] = hits
    if len(hits) >= max_hits:
        return True
    hits.append(now)
    return False


def audit(action, detail=""):
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "actor": session.get("user") or request.headers.get("X-API-Token", "?")[:8],
        "ip": request.remote_addr,
        "action": action,
        "detail": detail,
    }
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

ICONS = {
    "shield": "♢",
    "home": "⌂",
    "wallet": "▣",
    "card": "▤",
    "admin": "◈",
    "api": "</>",
    "logout": "↪",
    "lock": "◆",
    "activity": "◉",
    "users": "♙",
    "check": "✓",
    "arrow": "→",
}


LAYOUT = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>{{ title or "SecurePay" }}</title>
<style>
:root{
  --bg:#07111f;--panel:#0d1b2d;--panel2:#10233a;--line:#203550;
  --text:#eaf2ff;--muted:#8ea4bf;--accent:#43d9b0;--accent2:#5ca9ff;
  --danger:#ff6b81;--warning:#ffc857;--shadow:0 18px 50px rgba(0,0,0,.28);
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  color:var(--text);background:
  radial-gradient(circle at 15% 0%,rgba(67,217,176,.08),transparent 32%),
  radial-gradient(circle at 90% 10%,rgba(92,169,255,.10),transparent 30%),var(--bg);
}
a{color:inherit;text-decoration:none}
button,input{font:inherit}
.topbar{
  height:72px;border-bottom:1px solid var(--line);background:rgba(7,17,31,.84);
  backdrop-filter:blur(16px);position:sticky;top:0;z-index:10;
}
.nav{max-width:1180px;height:100%;margin:auto;padding:0 24px;display:flex;align-items:center;gap:26px}
.brand{display:flex;align-items:center;gap:11px;font-weight:800;letter-spacing:.2px;margin-right:auto}
.logo{
  width:38px;height:38px;border-radius:12px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--accent),var(--accent2));color:#04111d;font-weight:900;
  box-shadow:0 8px 24px rgba(67,217,176,.2)
}
.navlinks{display:flex;align-items:center;gap:5px}
.navlinks a{padding:10px 12px;border-radius:9px;color:var(--muted);font-size:14px}
.navlinks a:hover,.navlinks a.active{background:#13263c;color:var(--text)}
.userpill{padding:8px 12px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:13px}
.container{max-width:1180px;margin:0 auto;padding:42px 24px 70px}
.hero{display:grid;grid-template-columns:1.35fr .85fr;gap:22px;align-items:stretch}
.hero h1{font-size:clamp(38px,6vw,68px);line-height:1.02;letter-spacing:-2.8px;margin:12px 0 18px}
.hero p{color:var(--muted);font-size:17px;line-height:1.7;max-width:690px}
.eyebrow{display:inline-flex;align-items:center;gap:8px;color:var(--accent);font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:1.3px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 14px var(--accent)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:26px}
.btn{
  border:1px solid var(--line);border-radius:11px;padding:12px 17px;background:#102139;
  color:var(--text);font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:8px
}
.btn:hover{transform:translateY(-1px);border-color:#355170}
.btn.primary{background:linear-gradient(135deg,var(--accent),#54c7ef);border:0;color:#04111d}
.btn.danger{color:#ff9bab;border-color:rgba(255,107,129,.3);background:rgba(255,107,129,.08)}
.card{
  background:linear-gradient(180deg,rgba(16,35,58,.9),rgba(13,27,45,.94));
  border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow)
}
.hero-card{padding:25px;display:flex;flex-direction:column;justify-content:space-between}
.security-ring{
  width:112px;height:112px;border-radius:50%;margin:5px auto 22px;display:grid;place-items:center;
  background:conic-gradient(var(--accent) 0 82%,#18324b 82% 100%);
  position:relative
}
.security-ring:after{content:"";position:absolute;inset:9px;border-radius:50%;background:var(--panel)}
.security-ring span{position:relative;z-index:1;font-size:25px;font-weight:900}
.metric-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:13px;margin-top:22px}
.metric{padding:19px}.metric .label{color:var(--muted);font-size:12px}.metric .value{font-size:24px;font-weight:800;margin-top:6px}
.section-title{display:flex;align-items:end;justify-content:space-between;gap:20px;margin:52px 0 17px}
.section-title h2{margin:0;font-size:25px}.section-title p{margin:0;color:var(--muted);font-size:14px}
.features{display:grid;grid-template-columns:repeat(3,1fr);gap:15px}
.feature{padding:22px}.feature-icon{font-size:20px;color:var(--accent);margin-bottom:17px}.feature h3{margin:0 0 8px}.feature p{color:var(--muted);line-height:1.6;font-size:14px;margin:0}
.flash{padding:13px 15px;border-radius:11px;margin:0 0 18px;border:1px solid}
.flash.err{background:rgba(255,107,129,.09);border-color:rgba(255,107,129,.3);color:#ffadba}
.flash.ok{background:rgba(67,217,176,.08);border-color:rgba(67,217,176,.25);color:#87efd3}
.pagehead{margin-bottom:26px}.pagehead h1{font-size:36px;margin:7px 0}.pagehead p{color:var(--muted);margin:0}
.form-card{max-width:520px;padding:28px}
label{display:block;color:#b8c9dc;font-size:13px;font-weight:700;margin:17px 0 7px}
input{
  width:100%;padding:13px 14px;border-radius:10px;border:1px solid var(--line);
  background:#091729;color:var(--text);outline:none
}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(67,217,176,.08)}
.help{color:var(--muted);font-size:12px;line-height:1.55}
.stat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:18px}
.stat{padding:21px}.stat .big{font-size:29px;font-weight:900}.stat span{display:block;color:var(--muted);font-size:12px;margin-top:5px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.panel{padding:23px}.panel h3{margin:0 0 16px}
.balance{font-size:43px;font-weight:900;letter-spacing:-1.5px}.balance small{font-size:16px;color:var(--muted)}
.list{display:grid;gap:9px}.listitem{padding:13px;border:1px solid var(--line);border-radius:10px;background:rgba(7,17,31,.4)}
.listitem .top{display:flex;justify-content:space-between;gap:10px}.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.badge{display:inline-flex;padding:5px 8px;border-radius:999px;font-size:11px;font-weight:800;background:#163048;color:#91c6ff}
.badge.green{background:rgba(67,217,176,.1);color:#7ce8cc}
.badge.red{background:rgba(255,107,129,.1);color:#ff9aaa}
.tablewrap{overflow:auto}.table{width:100%;border-collapse:collapse;font-size:13px}.table th,.table td{text-align:left;padding:12px 10px;border-bottom:1px solid var(--line);white-space:nowrap}.table th{color:var(--muted);font-weight:700}
.domain-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:11px;margin-top:20px}
.domain{padding:14px;border:1px solid var(--line);border-radius:11px;background:#0a1829}.domain strong{display:block;font-size:13px}.domain span{display:block;color:var(--muted);font-size:11px;margin-top:5px}
.api-code{padding:18px;border-radius:12px;background:#06101d;border:1px solid var(--line);overflow:auto;color:#bfe7ff}
.footer{max-width:1180px;margin:auto;padding:0 24px 35px;color:#61758c;font-size:12px;display:flex;justify-content:space-between;gap:15px}
@media(max-width:850px){
 .hero,.grid2{grid-template-columns:1fr}.features{grid-template-columns:1fr 1fr}.domain-grid{grid-template-columns:1fr 1fr}
 .navlinks a:nth-child(n+3){display:none}.userpill{display:none}
}
@media(max-width:580px){
 .container{padding:28px 16px 55px}.nav{padding:0 16px}.features,.metric-grid,.stat-row{grid-template-columns:1fr}
 .hero h1{font-size:43px}.footer{padding:0 16px 25px;display:block}
}
</style>
</head>
<body>
<header class="topbar">
  <nav class="nav">
    <a class="brand" href="{{ url_for('home') }}"><span class="logo">S</span><span>SecurePay</span></a>
    <div class="navlinks">
      <a href="{{ url_for('home') }}">Home</a>
      {% if current_user %}
        <a href="{{ url_for('portal') }}">Portal</a>
        {% if current_role == "customer" %}<a href="{{ url_for('pay') }}">Payments</a>{% endif %}
        {% if current_role == "admin" %}<a href="{{ url_for('admin') }}">Admin</a>{% endif %}
      {% endif %}
      <a href="{{ url_for('api_docs') }}">API</a>
    </div>
    {% if current_user %}
      <span class="userpill">{{ current_user }} · {{ current_role }}</span>
      <a class="btn danger" href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a class="btn primary" href="{{ url_for('login') }}">Sign in</a>
    {% endif %}
  </nav>
</header>

<main class="container">
  {% if err %}<div class="flash err">⚠ {{ err }}</div>{% endif %}
  {% if msg %}<div class="flash ok">✓ {{ msg }}</div>{% endif %}
  {{ body|safe }}
</main>

<footer class="footer">
  <span>SecurePay Inc. · Security architecture prototype</span>
  <span>Tokenized demo payments · No real gateway connected</span>
</footer>
</body>
</html>
"""


def page(body, title="SecurePay", err=None, msg=None):
    return render_template_string(
        LAYOUT,
        body=body,
        title=title,
        err=err,
        msg=msg,
        current_user=session.get("user"),
        current_role=session.get("role"),
    )


# ---------------- www.securepay.example ----------------
@app.route("/")
def home():
    if session.get("user"):
        u = session["user"]
        role = users[u]["role"]
        if role == "customer":
            return redirect(url_for("portal"))
        if role == "admin":
            return redirect(url_for("admin"))

    body = """
    <section class="hero">
      <div>
        <div class="eyebrow"><span class="dot"></span> Secure payment architecture prototype</div>
        <h1>Payments built around security.</h1>
        <p>
          A multi-application SecurePay prototype demonstrating authentication, role-based access,
          card tokenization, API security, rate limiting and audit logging.
        </p>
        <div class="actions">
          <a class="btn primary" href="/login">Open SecurePay <span>→</span></a>
          <a class="btn" href="/api/docs">Explore API</a>
        </div>
        <div class="domain-grid">
          <div class="domain"><strong>Public</strong><span>securepay.example</span></div>
          <div class="domain"><strong>Portal</strong><span>portal.securepay.example</span></div>
          <div class="domain"><strong>Payments</strong><span>pay.securepay.example</span></div>
          <div class="domain"><strong>Admin</strong><span>admin.securepay.example</span></div>
          <div class="domain"><strong>API</strong><span>api.securepay.example</span></div>
        </div>
      </div>
      <div class="card hero-card">
        <div>
          <div class="eyebrow">Security posture</div>
          <div class="security-ring"><span>82%</span></div>
          <h3 style="text-align:center;margin:0">Defense-in-depth demo</h3>
          <p style="text-align:center;color:var(--muted);font-size:13px;line-height:1.6">
            Controls are enforced server-side across the simulated application domains.
          </p>
        </div>
        <div class="metric-grid">
          <div class="metric card"><div class="label">Auth</div><div class="value">RBAC</div></div>
          <div class="metric card"><div class="label">Cards</div><div class="value">Token</div></div>
          <div class="metric card"><div class="label">Logs</div><div class="value">Audit</div></div>
        </div>
      </div>
    </section>

    <div class="section-title"><div><h2>Security controls</h2><p>Implemented in the existing Flask prototype.</p></div></div>
    <section class="features">
      <div class="card feature"><div class="feature-icon">◆</div><h3>Authentication</h3><p>PBKDF2 password hashing, login rate limiting and session fixation protection.</p></div>
      <div class="card feature"><div class="feature-icon">◈</div><h3>Role isolation</h3><p>Customer and admin access are enforced on every protected route.</p></div>
      <div class="card feature"><div class="feature-icon">▣</div><h3>Tokenized cards</h3><p>The prototype stores only a generated token and last four digits instead of the full PAN.</p></div>
      <div class="card feature"><div class="feature-icon">◎</div><h3>API security</h3><p>Token authentication, admin API keys and per-token rate limiting protect API routes.</p></div>
      <div class="card feature"><div class="feature-icon">◉</div><h3>Audit trail</h3><p>Login, payment and authorization events are recorded in the audit ledger and log.</p></div>
      <div class="card feature"><div class="feature-icon">✓</div><h3>Secure headers</h3><p>Responses include defensive headers such as X-Frame-Options and no-store caching.</p></div>
    </section>
    """
    return page(body, "SecurePay — Secure Payment Platform")


# ---------------- Authentication ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page("""
        <div class="pagehead">
          <div class="eyebrow"><span class="dot"></span> Secure authentication</div>
          <h1>Welcome back.</h1>
          <p>Sign in to access your isolated SecurePay application.</p>
        </div>
        <div class="card form-card">
          <form method="post">
            <label>Username</label>
            <input name="username" autocomplete="username" placeholder="Enter username" required>
            <label>Password</label>
            <input name="password" type="password" autocomplete="current-password" placeholder="Enter password" required>
            <div class="actions"><button class="btn primary" type="submit">Sign in →</button></div>
          </form>
          <p class="help" style="margin-top:20px">Demo customer: <b>customer1</b> / <b>Cust#1234</b></p>
          <p class="help">Demo admin: <b>admin1</b> / <b>Adm!n#987</b></p>
        </div>
        """, "SecurePay — Login")

    u = request.form.get("username", "")
    p = request.form.get("password", "")
    key = f"login:{request.remote_addr}"
    if rate_limited(key, max_hits=5, window=60):
        audit("login_rate_limited", u)
        return page("<div class='pagehead'><h1>Sign in</h1><p>Please wait before trying again.</p></div>",
                    "SecurePay — Login", err="Too many attempts. Wait 60 seconds."), 429

    if u in users and check_password_hash(users[u]["hash"], p):
        session.clear()
        session["user"] = u
        session["role"] = users[u]["role"]
        audit("login_success", u)
        return redirect(url_for("home"))

    audit("login_failed", u)
    return page("<div class='pagehead'><h1>Sign in</h1><p>Check your credentials and try again.</p></div>",
                "SecurePay — Login", err="Invalid username or password."), 401


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
    <div class="pagehead">
      <div class="eyebrow"><span class="dot"></span> Customer portal</div>
      <h1>Hello, {u}.</h1>
      <p>Manage your account and review your security activity.</p>
    </div>
    <div class="stat-row">
      <div class="card stat"><span>Available balance</span><div class="big">₹{users[u]['balance']:.2f}</div></div>
      <div class="card stat"><span>Tokenized cards</span><div class="big">{len(cards.get(u, []))}</div></div>
      <div class="card stat"><span>Account role</span><div class="big">Customer</div></div>
    </div>
    <div class="grid2">
      <section class="card panel">
        <h3>Payment center</h3>
        <p class="muted">Make a mock payment using the secure tokenization flow.</p>
        <div class="actions"><a class="btn primary" href="/pay">Make a payment →</a></div>
      </section>
      <section class="card panel">
        <h3>Security status</h3>
        <p><span class="badge green">● Protected</span></p>
        <p class="muted">Session role checks, input validation and audit logging are active.</p>
      </section>
    </div>
    <div class="section-title"><div><h2>Recent activity</h2><p>Your latest audited events.</p></div></div>
    <section class="card panel list">
      {''.join(f"<div class='listitem'><div class='top'><strong>{t['action']}</strong><span class='muted mono'>{t['ts']}</span></div><div class='muted' style='margin-top:5px'>{t['detail'] or 'Security event recorded'}</div></div>" for t in user_tx[-10:]) or "<div class='listitem muted'>No activity yet.</div>"}
    </section>
    """
    return page(body, "SecurePay — Customer Portal")


# ---------------- pay.securepay.example ----------------
@app.route("/pay", methods=["GET", "POST"])
def pay():
    u = require_login("customer")
    if not u:
        return page("<div class='pagehead'><h1>Payments</h1></div>", "SecurePay — Payments",
                    err="Customer login required.")

    if request.method == "POST":
        number = request.form.get("card_number", "").replace(" ", "")
        name = request.form.get("holder", "").strip()
        amount = request.form.get("amount", "")

        if not re.fullmatch(r"\d{13,19}", number) or not luhn_check(number):
            return page("<div class='pagehead'><h1>Payment rejected</h1><p>Fix the card details and try again.</p></div>",
                        "SecurePay — Payments", err="Invalid card number.")

        if not name or len(name) > 50:
            return page("<div class='pagehead'><h1>Payment rejected</h1><p>Fix the cardholder name and try again.</p></div>",
                        "SecurePay — Payments", err="Invalid cardholder name.")

        try:
            amount = float(amount)
            assert 0 < amount <= users[u]["balance"]
        except (ValueError, AssertionError):
            return page("<div class='pagehead'><h1>Payment rejected</h1><p>Check the amount.</p></div>",
                        "SecurePay — Payments", err="Invalid amount.")

        card = tokenize_card(number, name)
        cards.setdefault(u, []).append(card)
        users[u]["balance"] -= amount
        audit("payment", f"{u} paid ₹{amount:.2f} via {card['last4']}")

        return page(f"""
        <div class="pagehead">
          <div class="eyebrow"><span class="dot"></span> Payment complete</div>
          <h1>Payment approved.</h1>
          <p>This is a simulated transaction for the security prototype.</p>
        </div>
        <div class="card panel">
          <span class="badge green">✓ Processed</span>
          <h2 style="font-size:38px;margin:15px 0">₹{amount:.2f}</h2>
          <p class="muted">Card reference: <span class="mono">****{card['last4']}</span></p>
          <p class="muted">Token: <span class="mono">{card['token']}</span></p>
          <div class="flash ok" style="margin-top:20px">Only a token + last4 were stored — never the full card number.</div>
          <div class="actions"><a class="btn primary" href="/portal">Back to portal</a></div>
        </div>
        """, "SecurePay — Payment Complete")

    return page(f"""
    <div class="pagehead">
      <div class="eyebrow"><span class="dot"></span> Secure payment application</div>
      <h1>Make a payment.</h1>
      <p>Demo-only payment flow with Luhn validation and card tokenization.</p>
    </div>
    <div class="grid2">
      <section class="card form-card" style="max-width:none">
        <div class="balance">₹{users[u]['balance']:.2f}<small> available</small></div>
        <form method="post">
          <label>Card number</label>
          <input name="card_number" inputmode="numeric" autocomplete="off" placeholder="4111 1111 1111 1111" required>
          <label>Cardholder name</label>
          <input name="holder" autocomplete="off" placeholder="Demo Customer" required>
          <label>Amount (INR)</label>
          <input name="amount" type="number" min="0.01" step="0.01" placeholder="100.00" required>
          <div class="actions"><button class="btn primary" type="submit">Pay securely →</button></div>
        </form>
      </section>
      <section class="card panel">
        <h3>Tokenization</h3>
        <p class="muted">The prototype generates a <span class="mono">tok_*</span> reference and stores only the final four digits.</p>
        <div class="list">
          {''.join(f"<div class='listitem'><div class='top'><strong>Card ••••{c['last4']}</strong><span class='badge'>Tokenized</span></div><div class='muted mono' style='margin-top:6px'>{c['token']}</div></div>" for c in cards.get(u, [])) or "<div class='listitem muted'>No tokenized cards yet.</div>"}
        </div>
        <p class="help" style="margin-top:18px">Do not enter real payment credentials. This project has no real payment gateway.</p>
      </section>
    </div>
    """, "SecurePay — Payments")


def luhn_check(num):
    total, alt = 0, False
    for d in reversed(num):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


# ---------------- admin.securepay.example ----------------
@app.route("/admin")
def admin():
    u = require_login("admin")
    if not u:
        audit("admin_access_denied", session.get("user", "anonymous"))
        return page("<div class='pagehead'><h1>Admin access</h1></div>", "SecurePay — Admin",
                    err="Admin access denied."), 403

    audit("admin_panel_access")
    body = f"""
    <div class="pagehead">
      <div class="eyebrow"><span class="dot"></span> Administration</div>
      <h1>Security command center.</h1>
      <p>Monitor users and the application audit ledger.</p>
    </div>
    <div class="stat-row">
      <div class="card stat"><span>Users</span><div class="big">{len(users)}</div></div>
      <div class="card stat"><span>Audit events</span><div class="big">{len(transactions)}</div></div>
      <div class="card stat"><span>API tokens</span><div class="big">{len(api_tokens)}</div></div>
    </div>
    <section class="card panel">
      <h3>User accounts</h3>
      <div class="tablewrap">
      <table class="table"><thead><tr><th>Username</th><th>Role</th><th>Balance</th><th>Status</th></tr></thead><tbody>
      {''.join(f"<tr><td><strong>{k}</strong></td><td><span class='badge'>{v['role']}</span></td><td>₹{v['balance']:.2f}</td><td><span class='badge green'>Active</span></td></tr>" for k,v in users.items())}
      </tbody></table>
      </div>
    </section>
    <div class="section-title"><div><h2>Audit ledger</h2><p>Latest security and payment events.</p></div></div>
    <section class="card panel">
      <div class="tablewrap">
      <table class="table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>IP</th><th>Detail</th></tr></thead><tbody>
      {''.join(f"<tr><td class='mono'>{t['ts']}</td><td>{t['actor']}</td><td><span class='badge'>{t['action']}</span></td><td class='mono'>{t['ip']}</td><td>{t['detail']}</td></tr>" for t in transactions[-30:]) or "<tr><td colspan='5' class='muted'>No events yet.</td></tr>"}
      </tbody></table>
      </div>
    </section>
    <div class="section-title"><div><h2>Admin API access</h2><p>Use the API key through the API interface.</p></div></div>
    <section class="card panel">
      <p class="muted">Current prototype key:</p>
      <div class="api-code mono">{ADMIN_API_KEY}</div>
      <p class="help">For a real deployment, keep ADMIN_API_KEY in environment variables and never expose it in a client-facing page.</p>
    </section>
    """
    return page(body, "SecurePay — Admin Dashboard")


# ---------------- api.securepay.example ----------------
@app.route("/api/docs")
def api_docs():
    return page("""
    <div class="pagehead">
      <div class="eyebrow"><span class="dot"></span> Developer interface</div>
      <h1>SecurePay API.</h1>
      <p>Token-authenticated endpoints from the existing prototype.</p>
    </div>
    <div class="grid2">
      <section class="card panel">
        <h3>Authentication</h3>
        <div class="api-code mono">POST /api/token
Content-Type: application/json

{"username":"customer1","password":"Cust#1234"}</div>
        <p class="muted">Returns an API token for authenticated calls.</p>
      </section>
      <section class="card panel">
        <h3>Security controls</h3>
        <div class="list">
          <div class="listitem"><strong>Token auth</strong><div class="muted">X-API-Token header</div></div>
          <div class="listitem"><strong>Rate limiting</strong><div class="muted">30 requests/minute per token</div></div>
          <div class="listitem"><strong>Audit logging</strong><div class="muted">API events are recorded</div></div>
        </div>
      </section>
    </div>
    <div class="section-title"><div><h2>Available endpoints</h2><p>Implemented by the current Flask backend.</p></div></div>
    <section class="card panel tablewrap">
      <table class="table">
        <thead><tr><th>Method</th><th>Endpoint</th><th>Auth</th><th>Purpose</th></tr></thead>
        <tbody>
          <tr><td><span class="badge green">POST</span></td><td class="mono">/api/token</td><td>Credentials</td><td>Issue API token</td></tr>
          <tr><td><span class="badge">GET</span></td><td class="mono">/api/v1/me</td><td>X-API-Token</td><td>Account information</td></tr>
          <tr><td><span class="badge">GET</span></td><td class="mono">/api/v1/transactions</td><td>X-API-Token</td><td>Customer transactions</td></tr>
          <tr><td><span class="badge">GET</span></td><td class="mono">/api/v1/users</td><td>X-Admin-Key</td><td>All users</td></tr>
        </tbody>
      </table>
    </section>
    """, "SecurePay — API")


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
    return jsonify({"username": u, "role": users[u]["role"], "balance": users[u]["balance"]})


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
    return jsonify({"users": [{"username": k, "role": v["role"]} for k, v in users.items()]})


# ---------------- Global security controls ----------------
@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(404)
def e404(e):
    return page("<div class='pagehead'><h1>404</h1><p>The requested SecurePay route was not found.</p><a class='btn primary' href='/'>Return home</a></div>",
                "SecurePay — Not Found", err="Not found."), 404


@app.errorhandler(500)
def e500(e):
    log.error("Internal error: %s", e)
    return "Internal server error.", 500


if __name__ == "__main__":
    app.run(debug=False, port=int(os.environ.get("PORT", 5000)))
