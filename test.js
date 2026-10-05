import { strict as assert } from "node:assert";

const base = process.env.TEST_URL || "http://127.0.0.1:8000";

const health = await fetch(`${base}/health`);
assert.equal(health.status, 200);
const healthJson = await health.json();
assert.equal(healthJson.ok, true);

const mcp = await fetch(`${base}/mcp`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "analyze_sql",
      arguments: { sql: "SELECT * FROM users WHERE email LIKE '%foo%'" }
    }
  })
});
assert.ok([200, 202].includes(mcp.status), `Unexpected MCP status: ${mcp.status}`);
console.log("smoke tests passed");
