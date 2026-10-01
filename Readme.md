
# Secure Multi-Domain Payment Company

## Problem Statement
A payment company operating a website, customer portal, payment app, admin portal and
APIs is a high-value target. Without separation of applications, strong authentication,
authorization, and audit logging, a single flaw can compromise the entire business.

## Objective
Demonstrate secure architecture for a multi-application payment company through a
working prototype. **No real payment gateway is integrated** — the goal is to show
understanding of security architecture and secure development.

## Architecture (Application/Domain Separation)
| Prefix | Simulated domain | Access |
|--------|------------------|--------|
| `/` | www.securepay.example | Public |
| `/portal` | portal.securepay.example | Authenticated users |
| `/pay` | pay.securepay.example | Customers only |
| `/admin` | admin.securepay.example | Admin role only |
| `/api` | api.securepay.example | API tokens / admin key |

In production these would be separate hostnames with isolated cookies, CSP, and
per-app deployment boundaries.

## Security Controls Demonstrated
- **Secure authentication** — salted PBKDF2 hashing, login rate limiting (5/min/IP),
  session fixation prevented via `session.clear()`
- **Authorization & RBAC** — customers cannot reach `/admin` or `/pay` as admins;
  forbidden attempts are audited
- **Session management** — server-side role checks on every request, secure logout
- **Input validation** — username pattern, Luhn card check, amount bounds
- **Payment security basics** — card **tokenization** (only `tok_*` + last4 stored,
  never the PAN), balance checks, transaction audit ledger
- **API security** — token-based auth (`X-API-Token`), separate admin API key,
  per-token rate limiting, JSON-only errors
- **Logging & monitoring** — every security event (logins, payments, denied access,
  rejected API keys) written to `payment_company.log` + in-app audit ledger
- **Secure communication** — security headers on all responses (HSTS flag included
  for production HTTPS)
- **Error handling** — generic errors, no stack traces leaked

## Technologies Used
- Python 3, Flask, Werkzeug Security, logging, secrets

## Installation / Setup
```bash
pip install flask
python app.py
```
Open http://localhost:5000
Demo accounts: `customer1 / Cust#1234`, `admin1 / Adm!n#987`

## How the Project Works
1. Login establishes a signed session; role is enforced server-side per route.
2. Customers manage tokenized cards and make (mock) payments; each payment is
   validated, tokenized, balance-checked and written to the audit ledger.
3. Admins get a monitoring dashboard of users and all audit events.
4. APIs issue random tokens (`POST /api/token`) and enforce rate limits per token.

## API Usage
```bash
curl -X POST localhost:5000/api/token -H "Content-Type: application/json" \
     -d '{"username":"customer1","password":"Cust#1234"}'
curl localhost:5000/api/v1/me -H "X-API-Token: <token>"
```


## Security Considerations
- Prototype uses in-memory storage; production needs a real DB with parameterized
  queries, encrypted card tokens at rest (KMS/HSM), and TLS everywhere (HSTS).
- Never log PANs or CVVs; comply with PCI-DSS scope minimization.
- Move secrets (`SECRET_KEY`, `ADMIN_API_KEY`) to environment variables/vault.

## Future Improvements
- MFA, webhook signing, fraud-rule engine, SIEM export, per-domain cookie isolation
  demo with subdomains, Docker deployment, unit/integration tests.
