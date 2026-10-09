const { spawn } = require("node:child_process");
const { createHash } = require("node:crypto");

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  const uploadUrl = process.env.BACKUP_UPLOAD_URL;
  if (!databaseUrl || !uploadUrl) throw new Error("DATABASE_URL and BACKUP_UPLOAD_URL are required; configure a presigned HTTPS PUT URL for durable offsite storage.");
  if (!/^https:\/\//i.test(uploadUrl)) throw new Error("BACKUP_UPLOAD_URL must use HTTPS.");
  const chunks = [];
  const child = spawn("pg_dump", [databaseUrl, "--format=custom", "--no-owner", "--no-acl"], { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stdout.on("data", chunk => chunks.push(chunk));
  child.stderr.on("data", chunk => { stderr += chunk.toString(); });
  const code = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", resolve);
  });
  if (code !== 0) throw new Error("pg_dump failed: " + stderr.slice(-2000));
  const backup = Buffer.concat(chunks);
  if (backup.length < 100) throw new Error("pg_dump produced an unexpectedly small backup.");
  const digest = createHash("sha256").update(backup).digest("hex");
  const response = await fetch(uploadUrl, { method: "PUT", headers: { "content-type": "application/octet-stream", "x-amz-meta-sha256": digest }, body: backup });
  if (!response.ok) throw new Error("Offsite backup upload failed with HTTP " + response.status);
  console.log(JSON.stringify({ event: "backup_complete", bytes: backup.length, sha256: digest, at: new Date().toISOString() }));
}
main().catch(error => { console.error(JSON.stringify({ event: "backup_failed", message: error.message })); process.exitCode = 1; });
