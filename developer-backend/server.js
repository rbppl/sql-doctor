const http = require("http");
const crypto = require("crypto");

const usage = new Map();

function json(res, status, body) {
  const out = JSON.stringify(body);
  res.writeHead(status, {"content-type":"application/json"});
  res.end(out);
}

function userId(req) {
  return req.headers["x-user-id"] || "anonymous";
}

function analyze(text) {
  const findings = [];
  const s = String(text || "");
  if (/select\s+\*/i.test(s)) findings.push({severity:"medium", message:"SELECT * can increase I/O and coupling.", fix:"Select only required columns."});
  if (/like\s+['"]%/i.test(s)) findings.push({severity:"high", message:"Leading wildcard LIKE usually prevents a normal B-tree index from being used.", fix:"Consider pg_trgm or a different search strategy."});
  if (/\bjoin\b/i.test(s) && !/\bon\b/i.test(s)) findings.push({severity:"high", message:"JOIN appears to have no ON condition.", fix:"Verify the join predicate."});
  return {score: Math.max(0, 100 - findings.length * 20), findings};
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") return json(res, 200, {ok:true, service:"developer-doctor-backend"});
  if (req.method === "GET" && req.url === "/api/usage") {
    const id = userId(req);
    return json(res, 200, {userId:id, analyses:usage.get(id)||0});
  }
  if (req.method === "POST" && req.url === "/api/analyze") {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => {
      try {
        const data = JSON.parse(body || "{}");
        const id = userId(req);
        usage.set(id, (usage.get(id)||0)+1);
        json(res, 200, {tool:data.tool||"developer", result:analyze(data.input||data.query||"")});
      } catch {
        json(res, 400, {error:"Invalid JSON request"});
      }
    });
    return;
  }
  json(res, 404, {error:"Not found"});
});

server.listen(process.env.PORT || 3000, "0.0.0.0");