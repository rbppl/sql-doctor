const assert = require("node:assert/strict");
const { scanGithubRepo } = require("./github-scanner");
const { analyze } = require("./analyzers");

function response(status, value) {
  return { ok: status >= 200 && status < 300, status, json: async () => value, headers: { get: () => null } };
}
function blob(path, contents) {
  return { path, type: "blob", size: Buffer.byteLength(contents), sha: "sha-" + path };
}
async function main() {
  const originalFetch = global.fetch;
  const requests = [];
  const contents = {
    "src/query.sql": "SELECT * FROM users WHERE email LIKE '%@example.com';",
    ".github/workflows/check.yml": "<<<<<<< HEAD\nname: CI\n=======\nname: Other\n>>>>>>> branch",
    "Dockerfile": "FROM node:latest\nEXPOSE 3000",
    "config.json": '{"ok":}',
    "README.md": "not scanned"
  };
  global.fetch = async (url) => {
    const parsed = new URL(url);
    requests.push(parsed);
    if (parsed.pathname.includes("/git/trees/")) {
      return response(200, { truncated: false, tree: Object.keys(contents).map(path => blob(path, contents[path])) });
    }
    const path = decodeURIComponent(parsed.pathname.split("/contents/")[1] || "");
    if (!(path in contents)) return response(404, { message: "Not found" });
    return response(200, { size: Buffer.byteLength(contents[path]), content: Buffer.from(contents[path]).toString("base64"), encoding: "base64" });
  };
  try {
    const result = await scanGithubRepo({ owner: "example", repo: "sample", branch: "feature/a b", token: "test-token", analyze });
    assert.equal(result.filesScanned, 4);
    assert.equal(result.filesConsidered, 4);
    assert.equal(result.analyzerVersion, "2.0.0");
    assert.ok(result.score < 100);
    assert.ok(result.counts.high >= 1);
    assert.ok(result.issues.some(x => x.file === "src/query.sql" && x.ruleId === "SQL001"));
    assert.ok(result.issues.some(x => x.file === ".github/workflows/check.yml" && x.ruleId === "GIT001"));
    assert.ok(result.issues.some(x => x.file === "Dockerfile" && x.ruleId === "DOCKER002"));
    assert.ok(result.issues.some(x => x.file === "config.json" && x.ruleId === "JSON001"));
    assert.ok(!result.issues.some(x => x.file === "README.md"));
    assert.ok(result.issues.every(x => x.file && x.tool && x.ruleId && x.severity && x.message && x.fix));
    assert.deepEqual(result.issues.map(x => x.file), [...result.issues.map(x => x.file)].sort((a,b) => a.localeCompare(b)));
    assert.ok(requests.some(x => x.pathname.includes("/git/trees/feature%2Fa%20b")));
    assert.ok(result.summary.includes("finding"));

    await assert.rejects(scanGithubRepo({ owner: "../bad", repo: "sample", token: "x", analyze }), /Invalid repository/);
    global.fetch = async () => response(200, { truncated: true, tree: [] });
    await assert.rejects(scanGithubRepo({ owner: "example", repo: "sample", token: "x", analyze }), /tree is too large/);
    global.fetch = async () => response(403, { message: "forbidden" });
    await assert.rejects(scanGithubRepo({ owner: "example", repo: "sample", token: "x", analyze }), /GitHub API 403/);
    console.log("GitHub scanner tests passed");
  } finally {
    global.fetch = originalFetch;
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
