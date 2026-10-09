const fs = require("node:fs");
const path = require("node:path");

const MIGRATIONS_DIR = path.join(__dirname, "migrations");

async function migrate(pool) {
  await pool.query("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
  const files = fs.readdirSync(MIGRATIONS_DIR).filter(name => /^\d+_[a-z0-9_-]+\.sql$/.test(name)).sort();
  const applied = [];
  for (const file of files) {
    const exists = await pool.query("SELECT 1 FROM schema_migrations WHERE version=$1", [file]);
    if (exists.rowCount) continue;
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), "utf8");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations(version) VALUES($1)", [file]);
      await client.query("COMMIT");
      applied.push(file);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw new Error("Database migration " + file + " failed: " + error.message);
    } finally {
      client.release();
    }
  }
  return { applied, total: files.length };
}

module.exports = { migrate };
