import { createServer } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const server = new McpServer(
  { name: "SQL Doctor", version: "1.0.0" },
  {
    instructions:
      "SQL Doctor performs a read-only static first-pass analysis of SQL. Never execute user SQL. Prefer explaining concrete risks, likely index opportunities, and safer rewrites. For stronger conclusions, ask for EXPLAIN (ANALYZE, BUFFERS) output and schema/index information."
  }
);

function uniq(arr) {
  return [...new Set(arr)];
}

function suggestIndexes(sql, db) {
  if (db.toLowerCase() !== "postgresql") return [];
  const suggestions = [];

  const where = sql.match(/\bwhere\s+(.+?)(?:\border\s+by\b|\bgroup\s+by\b|\blimit\b|$)/is)?.[1] || "";
  const order = sql.match(/\border\s+by\s+(.+?)(?:\blimit\b|$)/is)?.[1] || "";

  const eqCols = [...where.matchAll(/(?:^|and)\s*([a-zA-Z_][\w.]*)\s*=\s*(?:\$?\d+|'[^']*'|:[\w]+)/gi)]
    .map(m => m[1].replace(/^.*\./, ""));
  const orderCols = [...order.matchAll(/([a-zA-Z_][\w.]*)\s*(asc|desc)?/gi)]
    .map(m => m[1].replace(/^.*\./, ""));

  const table = sql.match(/\bfrom\s+([a-zA-Z_][\w.]*)/i)?.[1];
  if (table && (eqCols.length || orderCols.length)) {
    const cols = uniq([...eqCols, ...orderCols]);
    if (cols.length) {
      suggestions.push(
        `CREATE INDEX CONCURRENTLY idx_${table.replace(/\W/g, "_")}_${cols.join("_")} ON ${table} (${cols.join(", ")});`
      );
    }
  }
  return suggestions;
}

function analyzeSql(sql, explain = "", database = "PostgreSQL") {
  const q = sql.trim();
  const lower = q.toLowerCase();
  const findings = [];

  const add = (severity, title, detail, fix) =>
    findings.push({ severity, title, detail, fix });

  if (/\bselect\s+\*/i.test(q)) {
    add("medium", "SELECT *", "The query requests every column, which can increase I/O, network transfer, and memory usage.",
      "Select only the columns the application actually needs.");
  }

  if (!/\bwhere\b/i.test(q) && /\bfrom\b/i.test(q) && !/\bcount\s*\(\s*\*\s*\)/i.test(q)) {
    add("high", "No WHERE clause", "The query may read the entire source table.",
      "If a full scan is not intentional, add a selective predicate and verify the resulting plan.");
  }

  if (/\blike\s+['"]%/i.test(q)) {
    add("high", "Leading wildcard LIKE", "A normal B-tree index generally cannot efficiently seek into a value that starts with '%'.",
      database.toLowerCase() === "postgresql"
        ? "Consider pg_trgm/GiST or GIN indexing, full-text search, or a different lookup strategy."
        : "Consider the database's full-text/search indexing features.");
  }

  if (/\b(lower|upper|date|date_trunc|cast)\s*\(/i.test(q)) {
    add("medium", "Function on a column", "Applying a function/cast in a predicate can prevent a normal index from being used.",
      "Rewrite the predicate where possible or consider an expression/function-based index.");
  }

  if (/\bjoin\b/i.test(q) && !/\bon\b/i.test(q)) {
    add("high", "JOIN without ON", "This can create a Cartesian product or a much larger intermediate result.",
      "Verify that every JOIN has the intended join condition.");
  }

  if (/\border\s+by\b/i.test(q) && /\blimit\b/i.test(q)) {
    add("medium", "ORDER BY + LIMIT", "On a large table, sorting many rows before returning a small page can be expensive.",
      "Consider an index that supports the filtering columns and ordering columns together.");
  }

  if (/\bgroup\s+by\b/i.test(q) && !/\bwhere\b/i.test(q)) {
    add("medium", "Aggregation without filtering", "GROUP BY may process a large portion of the source table.",
      "If business logic permits, filter earlier and verify the aggregate plan.");
  }

  if (/\bor\b/i.test(lower) && /\bwhere\b/i.test(lower)) {
    add("info", "OR predicate", "OR conditions can make index selection harder depending on selectivity.",
      "Compare plans for the current query and alternatives such as UNION ALL when appropriate.");
  }

  if (/\bselect\b/i.test(q) && /\bdistinct\b/i.test(q)) {
    add("info", "DISTINCT", "DISTINCT may require sorting or hashing a large intermediate result.",
      "Verify that duplicates are actually possible and inspect the execution plan.");
  }

  if (explain) {
    const e = explain.toLowerCase();
    if (e.includes("seq scan") || e.includes("sequential scan")) {
      add("high", "Sequential Scan detected", "EXPLAIN output contains a sequential scan.",
        "Check table size, selectivity, statistics, and whether an appropriate index exists. A sequential scan is not automatically bad for small or low-selectivity tables.");
    }
    if (e.includes("rows removed by filter")) {
      add("medium", "Rows removed by filter", "The plan is reading rows that are later discarded.",
        "Check whether a selective index can reduce rows earlier in the plan.");
    }
    if (e.includes("sort method: external") || e.includes("disk")) {
      add("high", "Disk-based sort/materialization", "The plan suggests work spilling to disk.",
        "Inspect sort/hash memory settings and whether an index can avoid the sort.");
    }
    if (e.includes("nested loop")) {
      add("info", "Nested Loop", "Nested loops can be excellent for small outer relations but expensive with a large outer input.",
        "Check actual row counts and whether the inner side is indexed.");
    }
  }

  const high = findings.filter(f => f.severity === "high").length;
  const medium = findings.filter(f => f.severity === "medium").length;
  const score = Math.max(0, Math.min(100, 100 - high * 25 - medium * 10));

  return {
    database,
    score,
    verdict: score >= 80 ? "Looks reasonable" : score >= 55 ? "Needs investigation" : "Likely performance risk",
    findings,
    indexSuggestions: suggestIndexes(q, database),
    nextBestInput: explain
      ? "Schema + existing indexes + actual execution statistics would make this diagnosis more precise."
      : "For a stronger diagnosis, provide EXPLAIN (ANALYZE, BUFFERS) output plus table/index information.",
    safety: "Read-only static analysis. SQL is never executed by this server."
  };
}

server.tool(
  "analyze_sql",
  "Analyze SQL for common performance risks and suggest safer optimizations. Never executes SQL.",
  {
    sql: z.string().min(1),
    database: z.string().default("PostgreSQL"),
    explain: z.string().optional()
  },
  async ({ sql, database, explain }) => {
    const result = analyzeSql(sql, explain ?? "", database);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      structuredContent: result
    };
  }
);

const httpServer = createServer(async (req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, app: "SQL Doctor", version: "1.0.0" }));
    return;
  }

  if (req.url !== "/mcp") {
    res.writeHead(404);
    res.end("Not found");
    return;
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined
  });

  res.on("close", () => transport.close());

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res);
  } catch (error) {
    console.error(error);
    if (!res.headersSent) {
      res.writeHead(500);
      res.end("Internal server error");
    }
  }
});

const port = Number(process.env.PORT || 8000);
httpServer.listen(port, "0.0.0.0", () => {
  console.log(`SQL Doctor v1 listening on http://localhost:${port}/mcp`);
});