# Kluzar Accounts — Manual Cloudflare Setup Guide

**Owner performs every Cloudflare action below. Muse does not access the
Cloudflare dashboard, does not deploy anything, and does not change DNS.**

- Frontend: `https://accounts.kluzar.com` (GitHub Pages, from this repo)
- API Worker: `https://account-api.kluzar.com` (new, dedicated Worker)
- Database: Cloudflare D1, accessed ONLY through the Worker's `DB` binding.
  **D1 does not need a public URL and must never be exposed directly.**

No secrets, keys, passwords, or real credentials appear in this guide.
Everywhere a secret is needed, the guide says how to generate it and where
to put it — never what the value is.

---

## 0. Prerequisites

- GitHub repo: `ZainNaveed34211/login`, branch `main`, with `CNAME`
  containing `accounts.kluzar.com` (already in the repo — do not change it).
- Node.js 20+ and npm (for local tests only).
- `wrangler` CLI, logged in to the correct Cloudflare account:
  `npx wrangler login` (follow the browser prompts; this is your action).
- A Cloudflare account that already owns the `kluzar.com` zone and its DNS.
  Do not touch any existing Worker, DNS record, or zone setting for
  `kluzar.com` itself, for the SEO Worker, or for any other product.

## 1. Check the repository

```bash
git clone https://github.com/ZainNaveed34211/login.git
cd login
ls
# Expected: index.html, styles.css, app.js, config.js, logo.js, qr-lib.js,
#   wrangler.toml, worker/src/*.js, migrations/*.sql, tests/*.js,
#   docs/MANUAL-CLOUDFLARE-SETUP.md
node --test tests/*.test.js
# Expected: 23 tests, 23 pass, 0 fail (before any production setup)
```

## 2. Create the D1 database (new, dedicated)

```bash
npx wrangler d1 create kluzar-accounts
```

Copy the `database_id` from the output. It goes into `wrangler.toml`
in place of `REPLACE_WITH_REAL_D1_DATABASE_ID` — and nowhere else.
Do not publish the ID in public docs or screenshots.

## 3. Apply the migrations (in order)

```bash
npx wrangler d1 migrations apply kluzar-accounts --remote
```

This applies, in order:

1. `migrations/0001_users.sql` — users + entitlements
2. `migrations/0002_sessions_mfa.sql` — sessions, MFA secrets, one-time tokens
3. `migrations/0003_recovery_audit.sql` — recovery codes, recovery
   transactions, audit events

Verify:

```bash
npx wrangler d1 execute kluzar-accounts --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

You should see: `audit_events, entitlements, login_challenges,
mfa_secrets, pending_mfa_secrets, recovery_codes,
recovery_transactions, sessions, setup_tokens, users`.

Local test (does not touch production):

```bash
npx wrangler d1 migrations apply kluzar-accounts --local
```

## 4. Create the new Worker (do not touch existing Workers)

In the Cloudflare dashboard: Workers & Pages → Create → Worker →
name it exactly `kluzar-account-api`. Or from the repo root:

```bash
npx wrangler deploy
```

`wrangler.toml` already sets: name `kluzar-account-api`, entry
`worker/src/index.js`, compatibility date, and the D1 binding below.
If `wrangler deploy` asks to create a new Worker, confirm only for this
name. Never deploy over `kluzar-seo-audit` or any other Worker.

## 5. Bind D1 to the Worker

In the Worker → Settings → Bindings → Add binding → D1 Database:

- **Variable name (binding):** `DB` — exactly this, the code reads `env.DB`.
- **Database:** `kluzar-accounts` (the database from step 2).

Or in `wrangler.toml` (already present, just fill in the ID):

```toml
[[d1_databases]]
binding = "DB"
database_name = "kluzar-accounts"
database_id = "YOUR_REAL_D1_DATABASE_ID"
```

## 6. Configure environment variables and secrets

Public variables (in `wrangler.toml` `[vars]`, safe to keep in the file):

```toml
ALLOWED_ORIGINS = "https://accounts.kluzar.com"
ALLOW_LOCALHOST = "false"
ALLOW_INSECURE_COOKIE = "false"
PBKDF2_ITERATIONS = "600000"
```

Secret — set it with wrangler, never in a file, never in Git:

```bash
# Generate a fresh 32-byte key, then store it as a Worker secret.
# Run this on your own machine; do not share the output with anyone.
openssl rand -base64 32
npx wrangler secret put MFA_ENCRYPTION_KEY
# Paste the generated value when prompted.
```

This key encrypts MFA secrets at rest (AES-GCM). **If you lose it,
existing MFA secrets cannot be decrypted and affected users will need
to re-enrol MFA.** Store a backup of the key in your own password
manager, not in Git, not in a public doc, not in a screenshot.

## 7. Point the API hostname

In Cloudflare → DNS for `kluzar.com`, add a route for the Worker
(or a Workers custom domain) so the Worker answers at:

- `https://account-api.kluzar.com`

Do not change any other DNS record. The frontend origin that the Worker
allows is exactly `https://accounts.kluzar.com` (see `ALLOWED_ORIGINS`).
If you change the frontend hostname, update `ALLOWED_ORIGINS` and
`frontend/config.js` together, or logins will fail CORS checks.

## 8. GitHub Pages for the frontend

This frontend is static (plain HTML/CSS/JS, no build step). Options:

- **Recommended:** GitHub repo → Settings → Pages → Build and deployment
  → Source: **Deploy from a branch**, Branch: `main`, Folder: `/ (root)`.
  The repo root already contains `index.html` and `CNAME`
  (`accounts.kluzar.com`), so Pages will serve the account site directly.
- **CI (optional):** Add `.github/workflows/ci.yml` from this repo's
  workflow file via the GitHub website (the API cannot create workflow
  files — see section 11). The workflow runs tests and checks only;
  it does **not** deploy anything automatically. Keep it that way.

Wait for Pages to finish, then open `https://accounts.kluzar.com`
in a private browser window. The first screen must be the email entry,
not a dashboard, until you sign in.

## 9. Local development (optional, before production)

```bash
# Terminal 1: Worker (local D1, test key only — never a production key)
npx wrangler dev --local
# Terminal 2: frontend — edit config.js API_BASE_URL to your local
# Worker URL (for example http://localhost:8787) ONLY for local testing,
# and revert it to https://account-api.kluzar.com before any commit.
npx serve .
```

For local HTTP testing you may temporarily set
`ALLOW_INSECURE_COOKIE=true` and `ALLOW_LOCALHOST=true` in a local
`wrangler.toml` override — never commit those values, and never use
them in production, where cookies must be `Secure` + `SameSite=None`.

## 10. Deploy the Worker manually (after review)

1. Review the code on `main` (especially `worker/src/handlers.js`).
2. Confirm steps 2–7 are complete.
3. Deploy from the repo root: `npx wrangler deploy`.
4. Confirm the deployed Worker name is `kluzar-account-api` and that no
   other Worker was overwritten.

## 11. GitHub Actions workflow (paste-ready, website only)

The GitHub API cannot create or update `.github/workflows/*.yml`
files (workflows permission). That is why the workflow file is in this
repo's history as a local file, not pushed by the API. To enable CI:

1. On GitHub, go to the `login` repo → Add file → Create new file →
   path `.github/workflows/ci.yml`.
2. Paste the contents of the workflow file from the local copy
   (same name, in the repo's `.github/workflows/` folder in the
   working copy, or from the final report).
3. Commit directly to `main` from the website.
4. Check Actions → the workflow should run tests and frontend checks
   and pass. It deploys nothing.

## 12. Safe smoke tests (after deploy, no real user data needed)

Run these in order, in a private browser window, with a test email
you control. Use the real API hostname, not a test URL.

1. `GET https://account-api.kluzar.com/auth/session` without a cookie
   → `401`, `authenticated: false`, no `Set-Cookie` session.
2. On `https://accounts.kluzar.com`, create an account (email + a
   12+ character test password). You must be asked to set up an
   authenticator — no dashboard before that step.
3. Scan the QR code with your authenticator app (or enter the manual
   key). Enter the 6-digit code. You must see 10 recovery codes,
   once, with a download button.
4. After saving the codes, you must reach the dashboard. The
   Subscription section must show **Plan: free** and a **Get Premium**
   button linking to `https://payments.kluzar.com`.
5. Log out, log in again with email + password + a fresh authenticator
   code. The same code must not work twice in the same 30-second step.
6. Log in on a second browser/device, then use **Log out of all
   devices** from the first — the second session must stop working.
7. Try a wrong password twice in the login flow — the UI must return
   to email entry (server counters are not reset by this UI step).
8. **QR decode check (owner only):** scanning the QR code in step 3
   with a real authenticator app is the final QR verification. The QR
   image is generated locally in the browser by a maintained library
   (`qrcode`, MIT); it was not decoded by an authenticator app in
   automated tests, because tests have no authenticator app. If the QR
   does not scan, use the manual key shown on the same screen and
   report it — do not send the secret anywhere to "test" it.

## 13. Checking logs without exposing secrets

- Workers → `kluzar-account-api` → Logs. The Worker logs only
  structured events (`register`, `worker_error`) with user IDs and
  success flags — never passwords, codes, secrets, tokens, or hashes.
- If a log line ever contains a secret, rotate that secret immediately
  (MFA key: see section 6 warning; session tokens expire in 2 days
  and can be revoked via logout-all).

## 14. Backing up D1 and testing recovery

```bash
# Export (run on your own machine; store the backup privately)
npx wrangler d1 export kluzar-accounts --remote --output kluzar-accounts-backup.sql
# Restore test: create a second, throwaway D1 database, apply the backup
# there, and verify the tables — never restore over production without
# first testing on the throwaway database.
```

Test recovery at least once on a throwaway database before you rely on
backups. A backup that has never been restored is not a backup.

## 15. Diagnosing common errors

| Symptom | Likely cause | Fix (owner action) |
|---|---|---|
| `MFA_ENCRYPTION_KEY must be base64 of 32 bytes` (500) | Secret missing or wrong length | Re-run step 6 with a fresh `openssl rand -base64 32` value |
| Frontend shows CORS error on login | `ALLOWED_ORIGINS` does not include the exact frontend origin | Set it to `https://accounts.kluzar.com` exactly, redeploy |
| Login succeeds but dashboard shows "Session expired" | Cookie blocked (third-party cookie / `SameSite`) | Use the real hostnames (not localhost) in production; keep `Secure` + `SameSite=None` |
| "Setup session expired" on MFA setup | Setup token older than 30 minutes | Start again from sign-in / sign-up; do not reuse old tokens |
| 403 on profile save / password change | Missing or stale CSRF token | Reload the dashboard (fresh `/auth/session` gives a new token) and retry |
| Pages still shows the old empty page | Pages source is not `main` + `/ (root)`, or cache | Check section 8, then hard-reload; Pages can lag a few minutes |
| `database_id` placeholder error on deploy | `wrangler.toml` still has the placeholder | Fill in the real ID from step 2 |

## 16. What is NOT in this phase (do not claim otherwise)

- **Email verification is NOT implemented.** Accounts start as
  `email_verified = false` and the dashboard says so honestly.
  Do not claim an address is verified until an email provider is added.
- **Payment is NOT implemented.** Entitlements default to `free`.
  Get Premium only navigates to `https://payments.kluzar.com`;
  no checkout, price, or paid status is created here.
- **Global rate limiting is NOT implemented.** The Worker limit is
  per-isolate in-memory. Add a Cloudflare dashboard rate-limit rule
  in front of `account-api.kluzar.com` for a global limit, or use
  KV/Durable Objects later.
- **Idle timeout is NOT implemented.** Only the 2-day maximum
  session lifetime is enforced, server-side and in the cookie.
- **Email delivery, Google login, and admin tools are NOT included.**
  They are separate future phases, each needing their own review.
