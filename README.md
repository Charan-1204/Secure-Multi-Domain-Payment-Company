# Secure Multi-Domain Payment Company

A Flask-based secure payment platform prototype demonstrating a multi-domain application architecture with role-based access control, secure authentication, card tokenization, API security, rate limiting, and audit logging.

Live demo:
- https://secure-multi-domain-payment-company-djfq.onrender.com/

## Overview

This project simulates a payment company with separate application domains:

- Public website: `/`
- Customer portal: `/portal`
- Payment flow: `/pay`
- Admin dashboard: `/admin`
- API documentation and endpoints: `/api/docs`

The application is designed to showcase security patterns commonly used in prototype or demo payment systems, including:

- Session-based authentication
- Password hashing via Werkzeug
- Role-based access control
- Card tokenization and Luhn validation
- Rate limiting for login and API calls
- Audit logging for login, payments, and admin actions
- Security headers for HTTP responses

## Demo credentials

Customer:
- Username: `customer1`
- Password: `Cust#1234`

Admin:
- Username: `admin1`
- Password: `Adm!n#987`

## Features

### Authentication
- Passwords are hashed using Werkzeug's `generate_password_hash`
- Login attempts are rate-limited
- Sessions are used to enforce user and role checks

### Role-based access control
- Customer users can access the customer portal and payment flow
- Admin users can access the admin dashboard
- Non-admin access to admin routes is blocked

### Payment flow
- Card numbers are validated using Luhn check
- Full PAN values are not stored in the application data model
- Only card token and last four digits are retained as a demo representation of tokenization

### API security
- API clients authenticate using `X-API-Token`
- Admin endpoints require both a valid admin API token and `X-Admin-Key`
- API requests are rate-limited and audited

### Audit logging
- Payment, login, logout, and admin access events are recorded
- Audit entries include timestamp, actor, IP, action, and details

## Project structure

- `app.py` — main Flask application and routes
- `requirements.txt` — Python dependencies
- `payment_company.log` — runtime audit and application logs

## Local setup

1. Clone the repository
2. Create a virtual environment
3. Install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. Run the app

```bash
python app.py
```

5. Open the app in a browser at:

```text
http://127.0.0.1:5000/
```

## Notes

This is a prototype and demo application, not a production payment system. It is intended for educational and demonstration purposes only.

## License

This project is provided as-is for demonstration and educational use.
