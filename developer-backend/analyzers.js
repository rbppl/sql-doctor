const SEVERITY_WEIGHT = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
const VALID_TOOLS = new Set(["sql", "json", "api", "git", "docker", "developer"]);

function finding(ruleId, severity, title, message, fix, line) {
  return { ruleId, severity, title, message, fix, ...(Number.isInteger(line) ? { line } : {}) };
}
function lineOf(source, regex) {
  const match = regex.exec(source);
  return match ? source.slice(0, match.index).split("\n").length : undefined;
}
function stripSqlComments(source) {
  return source.replace(/--[^\n]*/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ");
}
function analyzeSql(source, findings) {
  const sql = stripSqlComments(source);
  const rules = [
    [/\bSELECT\s+\*\s+FROM\b/i, "SQL001", "medium", "Avoid SELECT *", "SELECT * can increase I/O and couple callers to schema changes.", "Select only the columns the caller needs."],
    [/\bLIKE\s+(['"])%[^\n]*?\1/i, "SQL002", "high", "Leading-wildcard LIKE", "A leading wildcard usually prevents a normal B-tree index from serving this predicate.", "Consider a trigram index (for PostgreSQL) or a search strategy designed for substring matching."],
    [/\b(?:UPDATE|DELETE)\s+(?:ONLY\s+)?[\w."\[\]]+\s+SET\b(?![\s\S]*?\bWHERE\b)/i, "SQL003", "high", "UPDATE without WHERE", "An UPDATE statement appears to modify every row because no WHERE clause was found.", "Add an intentional WHERE clause; use a transaction and verify affected-row counts."],
    [/\bDELETE\s+FROM\s+[\w."\[\]]+\s*;?\s*(?:$|\n)/i, "SQL004", "high", "DELETE without WHERE", "A DELETE statement appears to remove every row from its target table.", "Add an intentional WHERE clause and verify the target set before running it."],
    [/\bWHERE\s+(?:LOWER|UPPER|DATE|CAST)\s*\(\s*[\w."]+\s*\)/i, "SQL005", "medium", "Function on filtered column", "Applying a function to a filtered column may prevent use of a plain index on that column.", "Consider a matching expression index or rewrite the predicate to keep the indexed column bare."],
    [/\bNOT\s+IN\s*\(/i, "SQL006", "medium", "NOT IN predicate", "NOT IN can produce surprising results when the subquery or list contains NULL.", "Check NULL semantics; NOT EXISTS is often safer for subqueries."],
    [/\bSELECT\b[\s\S]*?\bFROM\b[\s\S]*?\bJOIN\b[\s\S]*?\bON\b/i, "SQL007", "medium", "Review join cardinality", "A join is present; incorrect or non-selective join keys can multiply rows and increase query cost.", "Verify join-key uniqueness and inspect an EXPLAIN (ANALYZE, BUFFERS) plan in a safe environment."]
  ];
  for (const [regex, id, severity, title, message, fix] of rules) {
    if (regex.test(sql)) findings.push(finding(id, severity, title, message, fix, lineOf(sql, regex)));
  }
  if (/\bSELECT\b/i.test(sql) && /\bFROM\b/i.test(sql) && !/\bLIMIT\s+\d+\b/i.test(sql) && !/\bCOUNT\s*\(/i.test(sql)) {
    findings.push(finding("SQL008", "low", "Unbounded result set", "This SELECT has no visible LIMIT; it may return more rows than the caller needs.", "Add pagination or a suitable LIMIT when the application does not require the full result set.", lineOf(sql, /\bSELECT\b/i)));
  }
}
function analyzeJson(source, findings) {
  let value;
  try { value = JSON.parse(source); }
  catch (error) {
    findings.push(finding("JSON001", "high", "Invalid JSON", "The input is not valid JSON: " + String(error.message).slice(0, 180), "Fix the reported syntax error; JSON requires double-quoted strings and property names."));
    return;
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const dangerous = /(^|[\s,{])["']?(?:__proto__|prototype|constructor)["']?\s*:/i;
    if (dangerous.test(source)) findings.push(finding("JSON002", "high", "Prototype-sensitive key", "The document contains a prototype-sensitive property name that can be unsafe when merged into JavaScript objects.", "Reject or explicitly handle __proto__, prototype, and constructor keys when data is later merged into objects."));
  }
  let depth = 0, maxDepth = 0, inString = false, escaped = false;
  for (const char of source) {
    if (inString) { if (escaped) escaped = false; else if (char === "\\") escaped = true; else if (char === '"') inString = false; continue; }
    if (char === '"') inString = true;
    else if (char === "{" || char === "[") { depth++; maxDepth = Math.max(maxDepth, depth); }
    else if (char === "}" || char === "]") depth--;
  }
  if (maxDepth > 40) findings.push(finding("JSON003", "medium", "Deeply nested JSON", "The document is nested more than 40 levels, which can stress downstream validators and consumers.", "Set a documented maximum nesting depth and reject unexpectedly deep input."));
  if (Buffer.byteLength(source, "utf8") > 100000) findings.push(finding("JSON004", "low", "Large JSON document", "The JSON input exceeds 100 KB.", "Consider pagination, streaming, or a request-size limit appropriate to the application."));
}
function analyzeApi(source, findings) {
  let parsed;
  try { parsed = JSON.parse(source); } catch {}
  const isOpenApi = /["']?(?:openapi|swagger)["']?\s*:/i.test(source) && /["']?paths["']?\s*:/i.test(source);
  if (isOpenApi && parsed && typeof parsed === "object") {
    if (!parsed.openapi && !parsed.swagger) findings.push(finding("API001", "high", "Missing API specification version", "The OpenAPI/Swagger document has no recognized specification version.", "Set a supported openapi version (or a valid Swagger 2.0 version)."));
    if (!parsed.info || !parsed.info.title || !parsed.info.version) findings.push(finding("API002", "medium", "Incomplete API metadata", "The API specification should include info.title and info.version.", "Add a descriptive title and version under info."));
    const paths = parsed.paths || {};
    if (!Object.keys(paths).length) findings.push(finding("API003", "medium", "No API paths", "The specification declares no endpoint paths.", "Add at least one path or remove the unused specification."));
    for (const [path, item] of Object.entries(paths)) {
      if (!item || typeof item !== "object") continue;
      for (const [method, operation] of Object.entries(item)) {
        if (!["get","put","post","delete","options","head","patch","trace"].includes(method.toLowerCase()) || !operation || typeof operation !== "object") continue;
        if (method.toLowerCase() === "get" && operation.requestBody) findings.push(finding("API004", "low", "GET request body", "GET " + path + " defines a requestBody, which is inconsistently supported by clients and intermediaries.", "Prefer query/path parameters for GET requests unless your API contract explicitly requires otherwise."));
        for (const match of path.matchAll(/\{([^}]+)\}/g)) {
          const param = match[1];
          const defined = [...(item.parameters || []), ...(operation.parameters || [])].some(p => p && p.in === "path" && p.name === param && p.required === true);
          if (!defined) findings.push(finding("API005", "medium", "Undeclared path parameter", "Path parameter {" + param + "} in " + path + " must be defined and required.", "Declare the parameter with in: path and required: true."));
        }
        if (!operation.responses || !Object.keys(operation.responses).length) findings.push(finding("API006", "high", "Missing operation responses", method.toUpperCase() + " " + path + " has no documented responses.", "Document at least the expected success response and relevant error responses."));
      }
    }
    const serialized = JSON.stringify(parsed);
    if (/https?:\/\//i.test(serialized) && /http:\/\//i.test(serialized)) findings.push(finding("API007", "medium", "Insecure HTTP server URL", "The specification includes an HTTP server URL that does not provide transport encryption.", "Use HTTPS for production endpoints, or clearly mark local-only HTTP servers."));
    const hasSecurity = !!parsed.security || Object.values(paths).some(item => item && Object.values(item).some(op => op && typeof op === "object" && op.security));
    if (!hasSecurity) findings.push(finding("API008", "low", "No declared security scheme usage", "No global or operation-level security requirements were found.", "If endpoints require authentication, define securitySchemes and apply security requirements; public APIs can intentionally omit them."));
    return;
  }
  if (/\b(?:access_token|api_key|secret|password)\s*[:=]\s*['"][^'"]{8,}['"]/i.test(source)) findings.push(finding("API010", "critical", "Possible hard-coded credential", "A credential-like value appears to be embedded in source code.", "Revoke exposed credentials and load secrets from a secret manager or environment configuration."));
  if (/\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(/i.test(source)) {
    if (/\b(?:req|request)\.body\b/i.test(source) && !/\b(?:zod|joi|ajv|yup|validate|schema\.parse|express-validator)\b/i.test(source)) findings.push(finding("API009", "medium", "Request body validation not evident", "Route code reads a request body but no common schema-validation call is evident in this file.", "Validate shape, types, lengths, and allowed fields at the API boundary."));
    if (/\bcors\s*\(\s*\)/i.test(source)) findings.push(finding("API011", "low", "Permissive CORS configuration", "Default CORS middleware may allow cross-origin access more broadly than intended.", "Restrict allowed origins to the frontends that need access."));
  }
}
function analyzeGit(source, findings) {
  const checks = [
    [/^(?:<<<<<<< .+|=======|>>>>>>> .+)$/m, "GIT001", "high", "Unresolved merge conflict", "Conflict markers remain in the file.", "Resolve the conflict and remove all conflict-marker lines."],
    [/(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})/, "GIT002", "critical", "Possible GitHub token", "A value resembles a GitHub access token.", "Revoke the token immediately, remove it from history, and use a secret manager."],
    [/(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/, "GIT003", "critical", "Private key in source", "A private-key header is present in the supplied text.", "Remove the key from the repository and rotate the credential."],
    [/\b(?:password|secret|api[_-]?key)\s*[:=]\s*["'][^"']{6,}["']/i, "GIT004", "high", "Possible hard-coded secret", "A secret-like assignment contains a literal value.", "Move the value to secret storage and rotate it if it was real."],
    [/\bgit\s+push\s+--force(?:\s|$)/i, "GIT005", "medium", "Force push command", "A force-push command can overwrite remote history.", "Prefer --force-with-lease and confirm the target branch and team workflow."],
    [/^\s*\.env(?:\.|$)/m, "GIT006", "low", "Environment file pattern", "The text appears to mention an .env file path.", "Ensure secret-bearing .env files are ignored and never committed; commit a sanitized .env.example instead."]
  ];
  for (const [regex, id, severity, title, message, fix] of checks) if (regex.test(source)) findings.push(finding(id, severity, title, message, fix, lineOf(source, regex)));
  if (/\bmain\b/i.test(source) && /\bmaster\b/i.test(source)) findings.push(finding("GIT007", "info", "Mixed default-branch names", "Both main and master appear; this may be intentional but can confuse scripts and branch policies.", "Standardize branch references where practical."));
}
function analyzeDocker(source, findings) {
  if (!/^\s*FROM\s+[^\n]+/im.test(source)) findings.push(finding("DOCKER001", "high", "Missing FROM instruction", "No FROM instruction was found in the Dockerfile.", "Choose an explicit, maintained base image."));
  if (/^\s*FROM\s+[^\n]*:\s*latest\b/im.test(source) || /^\s*FROM\s+[^\n]+\s*$/im.test(source) && /^\s*FROM\s+(?:node|python|nginx|ubuntu|alpine|debian|golang|openjdk)\s*$/im.test(source)) findings.push(finding("DOCKER002", "medium", "Floating base image tag", "A base image uses latest or an implicit default tag, making builds less reproducible.", "Pin a supported explicit tag; consider digest pinning for release builds."));
  if (!/^\s*USER\s+(?!root\b|0\b)[^\s]+/im.test(source)) findings.push(finding("DOCKER003", "medium", "Non-root user not configured", "No explicit non-root USER instruction was found.", "Create/use an unprivileged user when the application does not require root."));
  if (/^\s*ADD\s+/im.test(source)) findings.push(finding("DOCKER004", "low", "Review ADD usage", "ADD has extra behavior (such as remote URL fetching and archive extraction) beyond copying files.", "Prefer COPY unless you specifically need ADD's extra semantics."));
  if (/^\s*RUN\s+.*(?:apt-get|apk|yum)\s+install\b/im.test(source) && !/^\s*RUN\s+.*(?:rm\s+-rf\s+\/var\/lib\/apt\/lists|--no-cache)/im.test(source)) findings.push(finding("DOCKER005", "low", "Package-manager cache may remain", "A package-install layer may retain package-manager cache files.", "Combine installation and cache cleanup in the same RUN layer (or use the package manager's no-cache option)."));
  if (/^\s*EXPOSE\s+/im.test(source) && !/^\s*HEALTHCHECK\s+/im.test(source)) findings.push(finding("DOCKER006", "low", "No HEALTHCHECK", "The image declares an exposed port but no Docker HEALTHCHECK.", "Add a health check when the application has a reliable health endpoint."));
  if (/^\s*FROM\s+/im.test(source) && !/^\s*(?:CMD|ENTRYPOINT)\s+/im.test(source)) findings.push(finding("DOCKER007", "medium", "No startup instruction", "Dockerfile has no CMD or ENTRYPOINT.", "Add the intended startup command, unless this image is intentionally used only as a base/build stage."));
}
function analyze(tool, input) {
  const source = typeof input === "string" ? input : input == null ? "" : String(input);
  const findings = [];
  if (tool === "sql") analyzeSql(source, findings);
  else if (tool === "json") analyzeJson(source, findings);
  else if (tool === "api") analyzeApi(source, findings);
  else if (tool === "git") analyzeGit(source, findings);
  else if (tool === "docker") analyzeDocker(source, findings);
  else if (tool === "developer") {
    for (const type of ["sql", "json", "api", "git", "docker"]) {
      const result = analyze(type, source);
      findings.push(...result.findings);
    }
  } else if (VALID_TOOLS.has(tool)) {
    // Supported tool with no matching heuristic findings.
  }
  const penalty = findings.reduce((sum, item) => sum + (SEVERITY_WEIGHT[item.severity] ?? 0), 0);
  return {
    score: Math.max(0, 100 - penalty),
    findings,
    summary: findings.length ? findings.length + " finding" + (findings.length === 1 ? "" : "s") + " across " + new Set(findings.map(x => x.severity)).size + " severity level(s)." : "No heuristic issues detected.",
    analyzerVersion: "2.0.0"
  };
}
module.exports = { analyze };
