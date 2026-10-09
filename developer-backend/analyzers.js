function analyze(tool, input) {
  const source = String(input || "");
  const findings = [];

  if (tool === "sql" && /select\s+\*/i.test(source)) {
    findings.push({
      severity: "medium",
      message: "SELECT * can increase I/O and coupling.",
      fix: "Select only required columns."
    });
  }

  if (tool === "sql" && /like\s+['"]%/i.test(source)) {
    findings.push({
      severity: "high",
      message: "Leading wildcard LIKE usually prevents a normal B-tree index.",
      fix: "Consider pg_trgm."
    });
  }

  if (tool === "docker" && /FROM\s+/i.test(source) && !/(CMD|ENTRYPOINT)\b/i.test(source)) {
    findings.push({
      severity: "medium",
      message: "Dockerfile has no CMD or ENTRYPOINT.",
      fix: "Add the intended startup command."
    });
  }

  if (tool === "json") {
    try {
      JSON.parse(source);
    } catch {
      findings.push({
        severity: "high",
        message: "Invalid JSON.",
        fix: "Fix the JSON syntax."
      });
    }
  }

  return { score: Math.max(0, 100 - findings.length * 20), findings };
}

module.exports = { analyze };
