# THREATS.md — TrustVault threat model

## Assets and trust boundaries
Assets: document bytes, document metadata, user credentials, permission grants, audit history, audit HMAC key.
Trust boundaries: browser → Flask routes; Flask → SQLite; Flask → private filesystem; deployment host → operators/backups.

## Threats, controls, and residual risk

| Threat / attack | Mitigation implemented | Residual risk / accepted limitation |
|---|---|---|
| 1. Guess another document ID and open detail/download | `access()` checks owner or per-document grant on every object route | Must keep every future route behind the same check |
| 2. Call download URL directly without using UI | Download endpoint performs server-side ACL check before reading bytes | Already downloaded copies cannot be revoked |
| 3. Viewer changes URL ID to another owner's document | Object-level check uses authenticated user ID, not supplied owner ID | Regression tests should cover all new endpoints |
| 4. Viewer submits upload/edit/delete/grant POST manually | Role decorators and object checks; CSRF on state-changing requests | CSRF is not authorisation; both checks are required |
| 5. User has folder access and infers sibling files | No folder inheritance; grants are per-document only | No folder feature in this prototype |
| 6. Owner revokes access while viewer retains a valid session | Grant is read from DB on every request; no long-lived download token | In-flight response and previously downloaded file cannot be recalled |
| 7. Path traversal via filename (`../../secret`) | `secure_filename`, random storage key, storage path never built from user-supplied name | More robust filesystem isolation and malware scanning needed |
| 8. Upload executable or unsupported file | Extension allowlist; 10 MB cap; random name; not served inline | MIME is not deeply inspected; polyglot files and malware scanning remain |
| 9. Oversized upload exhausts resources | Flask request cap and read cap | Rate limits and quotas are not implemented |
| 10. Guess static URL to private file | Upload directory is outside static; no public file URL | Host filesystem permissions and backups must be secured |
| 11. SQL injection through form fields | Parameterised SQL for user-controlled values | Review any future dynamic SQL carefully |
| 12. Cross-site request forgery | Per-session CSRF token on authenticated state-changing routes | No CSP/security-header middleware yet |
| 13. Session theft / fixation | Session cleared on login; HttpOnly, SameSite; Secure cookie configurable | HTTPS and `COOKIE_SECURE=1` required in deployment; no MFA |
| 14. Brute-force login | Password hashing and generic failure message | Rate limiting, lockout and MFA not implemented |
| 15. Password disclosure from database | Werkzeug password hashing, no plaintext storage | Weak seed passwords are demo-only; rotate before deployment |
| 16. Audit event edited/deleted in DB | HMAC-SHA256 chained rows; verification view detects changes | Key compromise permits forgery; key is environment-based, not HSM-backed |
| 17. Audit key stored with database | Separate environment variable; do not commit `.env` | Host administrator may access environment; external WORM logging absent |
| 18. Failed access attempt not visible in audit | Failed login is logged; denied document requests are currently handled by generic error handler | 403 responses are logged as `access_denied` events by the central handler when the user is authenticated. Logging failure is reported to server logs and does not grant access; external durable alerting is still absent. |
| 19. Admin role used to read all documents | Admin deliberately does not bypass document ACL | Admin can see audit metadata and disable accounts |
| 20. Deactivated account reuses old session | Active status checked in `login_required` on every authenticated request | Current request already executing may complete |
| 21. Stored XSS in title/category/audit detail | Jinja autoescaping in templates | Avoid `|safe`; add CSP and input sanitisation as defence-in-depth |
| 22. Race condition between revoke and download | Each new request checks current grant | A download authorised just before revoke may finish |
| 23. Database/file deletion mismatch | Delete removes DB row then file; audit records deletion | Crash between DB and filesystem operations can leave orphaned file |
| 24. Audit chain concurrent writes | SQLite serialises writes in this small demo | Production needs transactional append-only service and concurrency testing |
| 25. Data loss / ransomware | Not implemented | Backups, recovery tests, encryption-at-rest, retention policy are future work |

## Security invariants
1. A document is downloadable only after `access(doc_id, "read")` succeeds.
2. A grantee cannot grant onward access; only owner-scoped grant/revoke routes are available.
3. Permission is checked on each request, not cached in a signed download URL.
4. Admin is not a document ACL superuser.
5. Files are not exposed through Flask's static file server.

## Deliberately not built
External sharing links, folder inheritance, version history, public registration, OCR/AI access recommendations, malware scanning, MFA/SSO, legal hold, retention automation, and enterprise WORM audit storage were excluded to keep the prototype focused on the core per-document authorisation boundary.
