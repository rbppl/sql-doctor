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
- `POST /api/auth/anonymous`, `POST /api/auth/logout`, `GET /api/me`.
- `GET /api/github/repos`, `GET /api/github/prs`, `POST /api/github/scan`, `POST /api/github/scan-pr`.
- `GET /api/usage`, `GET /api/history`, `POST /api/analyze`.

The analyzers are heuristic checks, not a replacement for code review or runtime testing.
