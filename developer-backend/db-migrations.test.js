const assert=require("node:assert/strict");
const {Pool}=require("pg");
const {migrate}=require("./db-migrations");

async function main(){
  if(!process.env.DATABASE_URL)throw new Error("DATABASE_URL is required for migration integration tests");
  const pool=new Pool({connectionString:process.env.DATABASE_URL});
  try{
    const first=await migrate(pool);
    assert.equal(first.total>=2,true);
    assert.deepEqual(first.applied,["001_core_schema.sql","002_billing.sql"]);
    const second=await migrate(pool);
    assert.deepEqual(second.applied,[]);
    const migrations=await pool.query("SELECT version FROM schema_migrations ORDER BY version");
    assert.deepEqual(migrations.rows.map(x=>x.version),["001_core_schema.sql","002_billing.sql"]);
    const columns=await pool.query("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='users'");
    const names=new Set(columns.rows.map(x=>x.column_name));
    for(const name of ["plan","github_id","stripe_customer_id","stripe_subscription_id","subscription_status","current_period_end"])assert.ok(names.has(name),"missing users."+name);
    const userId="migration-test-"+Date.now();
    await pool.query("INSERT INTO users(id,plan) VALUES($1,'free')",[userId]);
    await pool.query("INSERT INTO billing_events(event_id,event_type) VALUES('evt_migration_test','test') ON CONFLICT DO NOTHING");
    await pool.query("INSERT INTO billing_events(event_id,event_type) VALUES('evt_migration_test','test') ON CONFLICT DO NOTHING");
    const events=await pool.query("SELECT count(*)::int AS n FROM billing_events WHERE event_id='evt_migration_test'");
    assert.equal(events.rows[0].n,1);
    await pool.query("DELETE FROM users WHERE id=$1",[userId]);
    await pool.query("DELETE FROM billing_events WHERE event_id='evt_migration_test'");
    console.log("database migration integration tests passed");
  }finally{await pool.end()}
}
main().catch(e=>{console.error(e);process.exitCode=1});
