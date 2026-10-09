const assert = require("node:assert/strict");
const { analyze } = require("./analyzers");

function hasFinding(result, severity, fragment) {
  return result.findings.some(item => item.severity === severity && item.message.includes(fragment));
}

const selectStar = analyze("sql", "SELECT * FROM users");
assert.equal(selectStar.score, 80);
assert.ok(hasFinding(selectStar, "medium", "SELECT *"));

const leadingWildcard = analyze("sql", "SELECT id FROM users WHERE email LIKE '%@example.com'");
assert.equal(leadingWildcard.score, 80);
assert.ok(hasFinding(leadingWildcard, "high", "Leading wildcard"));

const combinedSql = analyze("sql", "SELECT * FROM users WHERE name LIKE '%admin%'");
assert.equal(combinedSql.score, 60);
assert.equal(combinedSql.findings.length, 2);

const dockerMissingCommand = analyze("docker", "FROM node:22-alpine\nWORKDIR /app");
assert.equal(dockerMissingCommand.score, 80);
assert.ok(hasFinding(dockerMissingCommand, "medium", "no CMD or ENTRYPOINT"));

const dockerWithEntrypoint = analyze("docker", "FROM node:22-alpine\nENTRYPOINT [\"node\", \"server.js\"]");
assert.equal(dockerWithEntrypoint.score, 100);
assert.equal(dockerWithEntrypoint.findings.length, 0);

const validJson = analyze("json", "{\"ok\":true,\"count\":2}");
assert.equal(validJson.score, 100);
assert.equal(validJson.findings.length, 0);

const invalidJson = analyze("json", "{\"ok\":}");
assert.equal(invalidJson.score, 80);
assert.ok(hasFinding(invalidJson, "high", "Invalid JSON"));

const unknownTool = analyze("unknown", "anything");
assert.equal(unknownTool.score, 100);
assert.deepEqual(unknownTool.findings, []);

console.log("analyzer regression tests passed");
