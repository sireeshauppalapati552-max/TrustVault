# PROMPTS.md — AI-assisted development log

> Replace the examples below with what you actually asked, observed, checked, and committed. Do not claim a commit exists until you have pushed it. Keep adding entries as you work; dates below are suggested slots, not proof of work.

## Reusable project context / instruction
"Act as a security-focused senior Flask engineer. Build a small document vault. Treat every document ID, filename, role and user ID from the browser as untrusted. Enforce object-level authorisation on the server for every read, download, edit, delete, grant and revoke route. Admin must not silently bypass document ACLs. Store bytes outside static. Include negative tests. Explain assumptions and residual risks; never claim production security without evidence."

## Entry 1 — 2026-11-10 — Project structure and role model
- Prompt asked: "Design a minimal Flask TrustVault with admin, owner and viewer roles, document-level read/edit grants, private file storage and clear role policy."
- Output produced: Flask route structure, SQLite tables, login and a role matrix.
- What I checked / what was wrong: [Write the specific mismatch you personally found while reviewing the generated code. Example: whether admin was incorrectly treated as an owner.]
- What I changed: [Describe your actual code review/fix.]
- Commit: [Paste the real GitHub commit URL after committing.]

## Entry 2 — 2026-11-10 — Object-level authorisation (security-critical)
- Prompt asked: "Review every document endpoint for IDOR/BOLA. Show how an unshared viewer could try direct GET/POST requests and make every route enforce a server-side ACL."
- Output produced: shared `access()` helper and per-route checks.
- What I checked / what was wrong: [Actually test a guessed document ID while logged in as viewer; record the observed HTTP status. Check download, detail, edit, delete, grant and revoke separately.]
- What I changed: [Record any missed route or corrected check.]
- Commit: [Real commit URL.]

## Entry 3 — 2026-11-10 — Revocation and audit integrity
- Prompt asked: "Design immediate per-request revocation and a tamper-evident audit chain. Explain key compromise and concurrency risks."
- Output produced: database grant deletion and HMAC-linked audit records.
- What I checked / what was wrong: [Verify whether an old session or previously downloaded copy remains usable; test whether changing a stored audit row is detected.]
- What I changed: [Record the actual test and correction.]
- Commit: [Real commit URL.]

## Entry 4 — 2026-11-10 — Upload validation and private storage
- Prompt asked: "Threat-model filename traversal, oversized uploads, unsupported extensions and public static-file exposure."
- Output produced: extension allowlist, upload cap, random storage IDs and private directory.
- What I checked / what was wrong: [Try an unsupported extension, oversized file and a filename containing traversal characters.]
- What I changed: [Record actual results and code changes.]
- Commit: [Real commit URL.]

## Entry 5 — 2026-11-10 — Automated negative tests
- Prompt asked: "Write tests proving an unshared user cannot view/download another owner's document, and that grant then revoke changes access."
- Output produced: Flask test-client tests.
- What I checked / what was wrong: [Run pytest. Remove or temporarily bypass one authorisation check and confirm the relevant test fails; restore the code immediately.]
- What I changed: [Record real test output and any repaired tests.]
- Commit: [Real commit URL.]

## Further prompt history
Add every meaningful prompt you reuse. Keep the prompt, generated result, specific defect found, your correction, and a real commit URL. If the AI output was correct, say what code path and test you independently inspected rather than inventing a mistake.
