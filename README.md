# TrustVault — secure document sharing prototype

A Flask + SQLite prototype with role-based login, per-document ACL grants, private file storage, CSRF protection, audit events and automated authorisation tests.

## Role policy

| Role | Allowed | Not allowed |
|---|---|---|
| Administrator | View user list, disable/enable accounts, inspect audit events and chain integrity | Does **not** automatically read/download documents or override document ACLs |
| Owner | Upload and manage own documents; grant/revoke named users' read/edit access; edit metadata; delete own documents | Cannot manage another owner's documents |
| Viewer | See and download only documents explicitly shared with them | Cannot upload, grant, revoke, edit, or delete |

A document owner has implicit full control over their own document. A named grant provides `read` or `edit` access. `edit` permits metadata changes, not replacing file bytes. Admin does not bypass ACL.

## Quick start (Windows PowerShell / VS Code)

1. Extract ZIP and open the `TrustVault` folder in VS Code.
2. Open Terminal → PowerShell and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = (py -c "import secrets; print(secrets.token_hex(32))")
$env:AUDIT_KEY = (py -c "import secrets; print(secrets.token_hex(32))")
py app.py
```

3. Open http://127.0.0.1:5000

Demo accounts (local demo only):
- Admin: `admin` / `Admin@12345`
- Owner: `owner` / `Owner@12345`
- Viewer: `viewer` / `Viewer@12345`
- Second viewer for cross-user tests: `viewer2` / `Viewer2@12345`
- Second owner: `owner2` / `Owner2@12345`

Seed accounts are created only when absent. For a fresh database, set strong `SEED_*_PASSWORD` environment variables before first run. Never deploy with demo passwords.

## Test

```powershell
pytest -q
```

Tests cover unshared document denial, grant/revoke behaviour, and viewer upload denial. Add more tests before production.

## Security design

- Every document detail/download/edit/delete/grant/revoke route checks the current user's server-side identity and document ownership/grant. Hiding buttons is not relied on.
- File bytes are stored under `private_uploads/`, never under `static/`; download is only through an authenticated route after ACL validation. Names are random server-generated identifiers.
- Revocation deletes the grant from the database. The next request performs a fresh ACL query, so the next download/detail request is denied. Already downloaded copies cannot be remotely recalled.
- Audit rows are chained with HMAC-SHA256; changing or deleting a row breaks verification. Keep `AUDIT_KEY` outside the database and back it up securely.
- Passwords are stored as Werkzeug password hashes. Session cookies are HttpOnly and SameSite=Lax. CSRF tokens are required on state-changing forms.
- Upload allowlist and 10 MB limit are enforced; original filename is not used as a storage path.

## Important limitations — be honest in your submission

This is a hackathon prototype, not a production-certified document vault. SQLite is suitable for a small demo, not high-concurrency production. The audit chain is tamper-evident only while the HMAC key remains secret; a privileged host/database attacker who also obtains the key can forge history. There is no external append-only/WORM log, malware scanning, content-disarm/reconstruction, antivirus, file encryption-at-rest, SSO/MFA, password reset, rate limiting, background retention, versioning, or recovery workflow. The current application does not implement public registration; seed accounts are used. Downloaded copies cannot be recalled. Admin account deactivation takes effect on the next request, because active status is checked on every authenticated request.

## Deploy

Use a Python host (Render, Railway, or a VM). Set `SECRET_KEY` and `AUDIT_KEY` to independent random secrets, set `COOKIE_SECURE=1` behind HTTPS, set strong seed passwords before first database creation, and configure persistent disk for both `DATABASE_PATH` and `PRIVATE_STORAGE`. Use a production WSGI server such as Gunicorn (`gunicorn app:app`) and add `gunicorn` to requirements. Do not use Flask's development server in production. Verify deployed HTTPS, persistent storage, and tests. This repository does not include a live deployment URL.

## API / route authorisation

| Method + route | Who may call | Enforcement |
|---|---|---|
| GET/POST `/login` | Anonymous | Password hash check |
| POST `/logout` | Authenticated | Login decorator + CSRF |
| GET `/dashboard` | Authenticated | Results filtered by role and grants |
| GET/POST `/upload` | Owner | Role decorator |
| GET `/document/<id>` | Owner or explicit read/edit grantee | `access()` |
| GET `/download/<id>` | Owner or explicit read/edit grantee | `access()` before file read |
| POST `/document/<id>/edit` | Owner or edit grantee | `access(...,"edit")` |
| POST `/document/<id>/delete` | Document owner only | ACL + owner check |
| POST `/document/<id>/grant` | Document owner only | Owner-scoped query |
| POST `/document/<id>/revoke/<user_id>` | Document owner only | Owner-scoped query |
| GET `/admin` | Admin | Role decorator |
| POST `/admin/user/<id>/toggle` | Admin | Role decorator + CSRF |

## Demo walkthrough

1. Login as owner and upload `sample.pdf` or `sample.txt`.
2. Open the document and grant `viewer` read access.
3. Logout, login as viewer, open and download the shared document.
4. Logout, login as owner, revoke viewer access.
5. Login as viewer again and show that download now returns 403.
6. Login as admin and show the permission grant/revoke/download events and audit integrity.
7. Run `pytest -q` and show the security tests.

## Submission checklist

- [ ] Push this folder to a **public** GitHub repository; make multiple real commits as you work. Do not fake commit dates/history.
- [ ] Deploy it and paste the real live URL here and into README.
- [ ] Change demo passwords and publish credentials safely for judge-only demo use.
- [ ] Run tests and capture actual passing output.
- [ ] Record a five-minute demo.
- [ ] Complete PROMPTS.md with actual prompts, observed mistakes, and real commit URLs. Never invent AI errors or commit links.
## Local Test Verification

- Security test suite executed using pytest.
- Verified document access restrictions.
- Verified permission grant and revocation.
- Verified viewer upload restrictions.
- Test result: 4 passed, 0 failed.