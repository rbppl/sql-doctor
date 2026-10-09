# SQL Doctor

SQL Doctor is a read-only MCP server that performs a static first-pass analysis of SQL queries. It **never executes user SQL**.

## What it does

- Detects common SQL performance smells: `SELECT *`, unfiltered reads, leading-wildcard `LIKE`, functions on filtered columns, suspicious joins, `ORDER BY + LIMIT`, unfiltered aggregation, `OR`, and `DISTINCT`.
- Reads PostgreSQL `EXPLAIN` text when supplied and flags sequential scans, rows removed by filters, disk-based sorts/materialization, and nested loops.
- Suggests candidate PostgreSQL indexes using simple heuristics.
- Returns a 0–100 diagnostic score, findings, fixes, and the next most useful input.

## Safety

SQL Doctor does not connect to a database and does not execute SQL. It only analyzes text supplied to the MCP tool.

## Run locally

```bash
npm install
npm start
```

Health check: `http://localhost:8000/health`
MCP endpoint: `http://localhost:8000/mcp`

## Docker

```bash
docker build -t sql-doctor .
docker run --rm -p 8000:8000 sql-doctor
```

## Smoke test

With the server running:

```bash
node test.js
```

## MCP tool

`analyze_sql`

Inputs:

- `sql` — SQL text (required)
- `database` — database name, defaults to PostgreSQL
- `explain` — optional EXPLAIN output

This is an MVP heuristic analyzer, not a replacement for a real database execution plan or DBA review.


## Developer Doctor backend

The SaaS backend includes heuristic analyzers for SQL, JSON, OpenAPI/API source, Git-related files, and Dockerfiles/Compose files. Findings include stable rule IDs, severity, a short explanation, a suggested fix, and (where available) a line number. Repository reports include a score, severity counts, scanned-file counts, and a report version.

Pull-request scans analyze supported files changed by the PR at its exact head commit rather than scanning the entire source branch. GitHub App check runs use the same changed-file scope. These are static heuristics: they do not execute SQL, build containers, call application endpoints, or prove that code is correct. Review findings before acting on them.

### Backend regression tests

Run from `developer-backend/`:

```bash
npm install
npm run check
npm test
```

The test suite covers analyzer rules and clean-input cases, HTTP/security smoke tests, OAuth state validation, token-encryption round trips/tamper detection, and deterministic repository-scanner tests with mocked GitHub API responses. CI runs these checks on pushes and pull requests.


## Developer Doctor SaaS and launch readiness

The connected SaaS frontend and backend are deployed separately on Render. The backend provides GitHub OAuth, repository and pull-request analysis, scan history, usage quotas, optional Stripe subscriptions, PostgreSQL migrations, health checks and protected metrics.

Before onboarding real users, follow [the first-user launch checklist](LAUNCH_CHECKLIST.md). Legal page templates are available at `frontend/imprint.html`, `frontend/privacy.html` and `frontend/terms.html`; they contain placeholders and must be completed and reviewed before public launch. Stripe payments and offsite backups also require explicit secret configuration and end-to-end verification.
