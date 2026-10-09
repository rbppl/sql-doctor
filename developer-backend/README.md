# Developer Doctor backend

Node.js HTTP API with PostgreSQL-backed accounts, sessions, analysis history, GitHub OAuth and repository scanning.

## Required production configuration

- `DATABASE_URL` — PostgreSQL connection string.
- `FRONTEND_URL` — exact browser origin allowed by CORS.
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_CALLBACK_URL` — GitHub OAuth App credentials and callback URL.
- `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_WEBHOOK_SECRET` — required for GitHub App pull-request webhooks.

Optional:
- `GITHUB_OAUTH_SCOPE` — defaults to `read:user user:email`. Do not add the OAuth `repo` scope casually: GitHub OAuth Apps grant broad repository permissions with that scope. For least-privilege private-repository scanning, prefer a GitHub App installed only on selected repositories with **Contents: read-only** permission.
- `GITHUB_TOKEN_ENCRYPTION_KEY` — dedicated 32-byte-or-stronger random secret (hex/base64 text is accepted). When configured, stored GitHub tokens are encrypted using AES-256-GCM format `enc:v2`; startup migrates existing `enc:v1` tokens using `GITHUB_CLIENT_SECRET`. Keep this secret stable and backed up. Without it, backward-compatible `enc:v1` encryption derives its key from `GITHUB_CLIENT_SECRET`.

## Security behavior

- OAuth state is stored server-side and bound to a short-lived HttpOnly cookie.
- OAuth callback issues a single-use, two-minute handoff code; the browser exchanges it for a server-side session.
- Session identifiers are random, only SHA-256 hashes are stored in PostgreSQL, and sessions expire after 30 days.
- Session cookies are HttpOnly, Secure and SameSite=None to support credentialed requests from the separately hosted frontend. A custom domain sharing one site is preferable if browser third-party-cookie restrictions interfere.
- Analysis requests are limited to 100 KB at the HTTP parser and 90 KB of actual analysis input.
- GitHub scans cap the file count, per-file size, total bytes, concurrency and request timeout.
- Per-user daily scan limits are reserved atomically in PostgreSQL to prevent parallel requests from bypassing the free tier.
- GitHub API errors are mapped to safe client messages; unexpected errors are logged without returning stack traces.

## Local checks

```bash
npm install
npm run check
npm test
```

The test suite covers API smoke checks, CORS/preflight, unauthenticated access, encryption round-trips and tamper detection, analyzer regressions, and OAuth state/scope behavior.

## Endpoints

- `GET /health` — database readiness.
- `GET /api/auth/github` and `GET /api/auth/github/callback` — OAuth.
- `POST /api/auth/exchange` — single-use OAuth handoff.
- `POST /api/auth/anonymous`, `POST /api/auth/logout`, `POST /api/account/delete`, `GET /api/me`.
- `GET /api/github/repos`, `GET /api/github/prs`, `POST /api/github/scan`, `POST /api/github/scan-pr`.
- `GET /api/usage`, `GET /api/history`, `POST /api/analyze`.

The analyzers are heuristic checks, not a replacement for code review or runtime testing.

## Plans and Stripe subscriptions

- **Free:** 20 analyses per user per UTC/database-local day.
- **Pro:** up to `PRO_DAILY_LIMIT` analyses per day (default 1,000).
- Checkout and the Stripe customer portal are available at `POST /api/billing/checkout` and `POST /api/billing/portal`.
- The signed webhook is `POST /api/billing/webhook`. It handles Checkout completion, subscription lifecycle events, and failed invoices. Event IDs are stored to make webhook retries idempotent.
- Billing is deliberately disabled until Stripe settings are configured. Add `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, and `STRIPE_WEBHOOK_SECRET` to Render. Create a recurring monthly Stripe Price, then register the webhook endpoint and subscribe to `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, and `invoice.payment_failed`. Keep test keys/prices for staging and live keys/prices for production; never commit secrets.
- A Pro plan grants higher usage only. It does not bypass GitHub permissions or guarantee finding-free code.

## Database migrations

SQL migrations live in `migrations/` and are applied in filename order at startup. Applied versions are tracked in `schema_migrations`; each migration runs in a transaction. Add new numbered migration files instead of editing an already-applied migration. CI runs the migrations twice against a temporary PostgreSQL service to verify clean install and idempotent upgrade behavior.

## Backups and restore

The scheduled GitHub Actions workflow `.github/workflows/database-backup.yml` runs daily at 03:30 UTC. Configure these repository secrets before relying on it:

- `BACKUP_DATABASE_URL`: Render **external** PostgreSQL connection URL, since GitHub-hosted runners cannot use Render's private database hostname.
- `BACKUP_S3_URI`: S3 bucket/prefix such as `s3://your-private-bucket/developer-doctor/`.
- `BACKUP_AWS_ACCESS_KEY_ID`, `BACKUP_AWS_SECRET_ACCESS_KEY`, and `BACKUP_AWS_REGION`: a dedicated IAM identity limited to writing/listing objects in that backup prefix.

The job skips with a warning until all secrets exist. The backup is a PostgreSQL custom-format dump, uploaded with S3 server-side AES-256 encryption and a SHA-256 checksum in object metadata. Configure a bucket lifecycle rule (for example, 30-day expiry) and block public access. Use a dedicated bucket and least-privilege IAM policy. Run the workflow manually once after configuration and verify the object exists.

To restore, download a dump to a controlled machine and test it against a **separate** PostgreSQL database first: `pg_restore --no-owner --no-acl --dbname="$RESTORE_DATABASE_URL" developer-doctor.dump`. Never test restoration by overwriting production. A backup is not considered verified until a restore test succeeds.

## Monitoring and CI/CD

- `GET /health` is a public readiness check. It verifies PostgreSQL connectivity and reports database latency and process uptime; use it for an external uptime monitor.
- `GET /metrics` exposes Prometheus-format process counters only when `MONITORING_BEARER_TOKEN` is configured. Supply it as an Authorization Bearer token; keep it private. Counters reset when the process restarts.
- Render provides service logs and CPU/memory metrics. Configure alerts in Render and an external uptime monitor for `/health`.
- GitHub Actions runs syntax checks, unit/regression tests, and PostgreSQL migration integration tests on pushes and pull requests. Render auto-deploys committed revisions; verify both service deploys and the health endpoint after releases.
- The current Render PostgreSQL instance is on a free plan and has a known expiry date. Migrate/upgrade it before expiry and verify an offsite backup and restore before deleting the old database.


## First-user launch gate

See the repository-root `LAUNCH_CHECKLIST.md` before inviting users. Legal pages are published as templates under `frontend/imprint.html`, `frontend/privacy.html`, and `frontend/terms.html`; they intentionally contain visible placeholders and are not launch-ready until the operator completes and reviews them. Account deletion removes local account data and scan history and attempts to revoke the GitHub OAuth grant. Active subscriptions must be cancelled first. Stripe's legally retained billing records and backups under the configured retention policy may remain.
