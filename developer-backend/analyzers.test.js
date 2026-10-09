const assert = require("node:assert/strict");
const { analyze } = require("./analyzers");

function rule(result, id) { return result.findings.find(item => item.ruleId === id); }
function expectRule(tool, input, id, severity) {
  const result = analyze(tool, input);
  const item = rule(result, id);
  assert.ok(item, tool + " should report " + id + "; got " + JSON.stringify(result.findings));
  if (severity) assert.equal(item.severity, severity);
  assert.ok(item.message && item.fix && item.title);
  assert.ok(Number.isInteger(item.line) || item.line === undefined);
  assert.ok(result.score >= 0 && result.score <= 100);
  assert.equal(result.analyzerVersion, "2.0.0");
  return result;
}

// SQL: useful detections, combinations, and comment false-positive guard.
expectRule("sql", "SELECT * FROM users;", "SQL001", "medium");
expectRule("sql", "SELECT id FROM users WHERE email LIKE '%@example.com';", "SQL002", "high");
expectRule("sql", "UPDATE users SET active = false;", "SQL003", "high");
expectRule("sql", "DELETE FROM sessions;", "SQL004", "high");
expectRule("sql", "SELECT * FROM users WHERE LOWER(email) = 'x';", "SQL005", "medium");
expectRule("sql", "SELECT id FROM users WHERE id NOT IN (SELECT user_id FROM blocked);", "SQL006", "medium");
expectRule("sql", "SELECT u.id FROM users u JOIN teams t ON t.id = u.team_id;", "SQL007", "medium");
expectRule("sql", "SELECT id FROM users;", "SQL008", "low");
const commentedSql = analyze("sql", "-- SELECT * FROM hidden\nSELECT id FROM users LIMIT 10;");
assert.equal(rule(commentedSql, "SQL001"), undefined);
assert.equal(rule(commentedSql, "SQL008"), undefined);
const combinedSql = analyze("sql", "SELECT * FROM users WHERE name LIKE '%admin%';");
assert.ok(rule(combinedSql, "SQL001") && rule(combinedSql, "SQL002"));
assert.ok(combinedSql.score < 100);

// JSON: parser errors, prototype-sensitive keys, deep nesting, valid empty/scalar JSON.
expectRule("json", '{"ok":}', "JSON001", "high");
expectRule("json", '{"__proto__":{"admin":true}}', "JSON002", "high");
expectRule("json", "[".repeat(41) + "0" + "]".repeat(41), "JSON003", "medium");
assert.equal(analyze("json", '{"ok":true,"count":2}').findings.length, 0);
assert.equal(analyze("json", '"plain scalar"').findings.length, 0);
assert.equal(analyze("json", "null").score, 100);

// API: OpenAPI metadata, response definitions, path parameters, GET bodies and HTTP.
expectRule("api", JSON.stringify({
  openapi: "3.0.3",
  info: { title: "Example", version: "1.0" },
  servers: [{ url: "http://api.example.test" }],
  paths: { "/users/{id}": { get: { requestBody: { required: false }, responses: {} } } }
}), "API004", "low");
expectRule("api", JSON.stringify({
  openapi: "3.0.3",
  info: { title: "Example", version: "1.0" },
  paths: { "/users/{id}": { get: { responses: {} } } }
}), "API005", "medium");
expectRule("api", JSON.stringify({
  openapi: "3.0.3", info: { title: "Example", version: "1.0" },
  paths: { "/users": { get: {} } }
}), "API006", "high");
expectRule("api", "app.post('/login', (req, res) => { const x = req.body; res.send(x); });", "API009", "medium");
expectRule("api", "const api_key = 'super-secret-value';", "API010", "critical");

// Git: conflict markers, credential leaks, keys, risky history edits and env paths.
expectRule("git", "<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch", "GIT001", "high");
expectRule("git", "const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';", "GIT002", "critical");
expectRule("git", "-----BEGIN PRIVATE KEY-----\nsecret", "GIT003", "critical");
expectRule("git", "password = 'my-long-password';", "GIT004", "high");
expectRule("git", "git push --force origin main", "GIT005", "medium");
expectRule("git", ".env.production", "GIT006", "low");

// Docker: reproducibility, least privilege, copy semantics, cache and startup.
expectRule("docker", "FROM node:latest\nEXPOSE 3000\nADD app.tar.gz /app\nRUN apt-get install -y curl", "DOCKER002", "medium");
expectRule("docker", "FROM node:22-alpine\nWORKDIR /app", "DOCKER003", "medium");
expectRule("docker", "FROM node:22-alpine\nUSER node\nADD app.tar.gz /app\nCMD [\"node\",\"server.js\"]", "DOCKER004", "low");
expectRule("docker", "FROM ubuntu:24.04\nRUN apt-get install -y curl\nEXPOSE 8080", "DOCKER005", "low");
expectRule("docker", "FROM node:22-alpine\nEXPOSE 3000\nUSER node\nCMD [\"node\",\"server.js\"]", "DOCKER006", "low");
expectRule("docker", "FROM node:22-alpine\nWORKDIR /app", "DOCKER007", "medium");
assert.equal(analyze("docker", "FROM node:22-alpine\nUSER node\nCMD [\"node\",\"server.js\"]").findings.length, 0);

// Contract and boundary behavior.
const clean = analyze("sql", "SELECT id FROM users WHERE id = 1 LIMIT 1;");
assert.equal(clean.score, 100);
assert.deepEqual(clean.findings, []);
assert.match(clean.summary, /No heuristic issues/);
assert.equal(analyze("unknown", "anything").score, 100);
assert.deepEqual(analyze("unknown", "anything").findings, []);
assert.equal(analyze("developer", "SELECT * FROM users").findings.some(x => x.ruleId === "SQL001"), true);
assert.equal(analyze("sql", null).score, 100);
console.log("analyzer unit tests passed");
