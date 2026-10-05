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
