const http=require("http");
const crypto=require("crypto");
const{Pool}=require("pg");
const{scanGithubRepo}=require("./github-scanner");
const{githubLogin,githubCallback,githubJson}=require("./github-oauth");
const{encryptToken,decryptToken}=require("./github-crypto");

const pool=process.env.DATABASE_URL?new Pool({
  connectionString:process.env.DATABASE_URL,
  ssl:process.env.DATABASE_URL.includes("render.com")?{rejectUnauthorized:false}:undefined
}):null;
const FREE_LIMIT=20;
const FRONTEND_URL=(process.env.FRONTEND_URL||"https://developer-doctor-frontend.onrender.com").replace(/\/$/,"");

async function init(){
  if(!pool)return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,created_at TIMESTAMPTZ DEFAULT now(),plan TEXT NOT NULL DEFAULT 'free');
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at TIMESTAMPTZ DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL);
    CREATE TABLE IF NOT EXISTS analyses(id BIGSERIAL PRIMARY KEY,user_id TEXT NOT NULL,tool TEXT NOT NULL,input TEXT NOT NULL,result JSONB NOT NULL,created_at TIMESTAMPTZ DEFAULT now());
    CREATE INDEX IF NOT EXISTS analyses_user_created_idx ON analyses(user_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS oauth_states(state TEXT PRIMARY KEY,created_at TIMESTAMPTZ DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL);
    CREATE TABLE IF NOT EXISTS oauth_handoffs(code TEXT PRIMARY KEY,token_hash TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS github_id TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS github_login TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS github_email TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS github_access_token TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS users_github_id_idx ON users(github_id) WHERE github_id IS NOT NULL;
  `);
  if(process.env.GITHUB_CLIENT_SECRET){
    const legacy=await pool.query("SELECT id,github_access_token FROM users WHERE github_access_token IS NOT NULL AND github_access_token NOT LIKE $1",["enc:v1:%"]);
    for(const row of legacy.rows)await pool.query("UPDATE users SET github_access_token=$1 WHERE id=$2",[encryptToken(row.github_access_token),row.id]);
  }
}

function hash(t){return crypto.createHash("sha256").update(t).digest("hex")}

function originAllowed(origin){
  return !origin||origin===FRONTEND_URL;
}

function json(res,status,b){
  res.writeHead(status,{
    "content-type":"application/json; charset=utf-8",
    "cache-control":"no-store",
    "x-content-type-options":"nosniff",
    "referrer-policy":"same-origin",
    "access-control-allow-origin":FRONTEND_URL,
    "access-control-allow-credentials":"true",
    "access-control-allow-headers":"Authorization,Content-Type",
    "access-control-allow-methods":"GET,POST,OPTIONS"
  });
  res.end(JSON.stringify(b));
}

function cookie(res,name,value,maxAge){
  res.setHeader("Set-Cookie",`${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

function clearCookie(res,name){
  res.setHeader("Set-Cookie",`${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

function authToken(req){
  const bearer=String(req.headers.authorization||"").match(/^Bearer\\s+(.+)$/i);
  if(bearer)return bearer[1];
  const cookies=String(req.headers.cookie||"").split(";").map(x=>x.trim());
  const session=cookies.find(x=>x.startsWith("dd_session="));
  return session?decodeURIComponent(session.slice("dd_session=".length)):null;
}

async function user(req){
  const token=authToken(req);
  if(!pool||!token)return null;
  const r=await pool.query(
    "SELECT s.user_id,u.plan,u.github_access_token,u.github_login,u.github_email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()",
    [hash(token)]
  );
  if(!r.rowCount)return null;
  r.rows[0].github_access_token=decryptToken(r.rows[0].github_access_token);
  return r.rows[0];
}

async function usageCount(id){
  const r=await pool.query("SELECT count(*)::int n FROM analyses WHERE user_id=$1 AND created_at>=date_trunc('day',now())",[id]);
  return r.rows[0].n;
}

function analyze(t,x){
  const s=String(x||""),f=[];
  if(t==="sql"&&/select\\s+\\*/i.test(s))f.push({severity:"medium",message:"SELECT * can increase I/O and coupling.",fix:"Select only required columns."});
  if(t==="sql"&&/like\\s+['"]%/i.test(s))f.push({severity:"high",message:"Leading wildcard LIKE usually prevents a normal B-tree index.",fix:"Consider pg_trgm."});
  if(t==="docker"&&/FROM\\s+/i.test(s)&&!/(CMD|ENTRYPOINT)\\b/i.test(s))f.push({severity:"medium",message:"Dockerfile has no CMD or ENTRYPOINT.",fix:"Add the intended startup command."});
  if(t==="json")try{JSON.parse(s)}catch(e){f.push({severity:"high",message:"Invalid JSON.",fix:"Fix the JSON syntax."})}
  return{score:Math.max(0,100-f.length*20),findings:f};
}

function body(req){
  return new Promise((resolve,reject)=>{
    let s="";
    req.on("data",c=>{
      s+=c;
      if(s.length>100000){req.destroy();reject(new Error("Request too large"))}
    });
    req.on("end",()=>{
      try{resolve(JSON.parse(s||"{}"))}catch(e){reject(e)}
    });
    req.on("error",reject);
  });
}

async function main(){
  await init();
  const server=http.createServer(async(req,res)=>{
    try{
      const url=new URL(req.url,"http://localhost"),path=url.pathname,origin=req.headers.origin;
      if(req.method==="OPTIONS"){
        if(!originAllowed(origin))return json(res,403,{error:"Origin not allowed"});
        return json(res,204,{});
      }
      if(!originAllowed(origin))return json(res,403,{error:"Origin not allowed"});

      if(req.method==="GET"&&(path==="/"||path==="/health")){
        let database=true;
        if(pool){
          try{await pool.query("SELECT 1")}catch(e){database=false}
        }else database=false;
        return json(res,database?200:503,{ok:database,database,service:"developer-doctor-backend"});
      }

      if(req.method==="GET"&&path==="/api/auth/github"){
        if(!process.env.GITHUB_CLIENT_ID||!process.env.GITHUB_CLIENT_SECRET||!process.env.GITHUB_CALLBACK_URL)return json(res,503,{error:"GitHub OAuth is not configured"});
        return res.writeHead(302,{Location:await githubLogin(pool)}).end();
      }

      if(req.method==="GET"&&path==="/api/auth/github/callback"){
        const code=url.searchParams.get("code"),state=url.searchParams.get("state");
        if(!code||!state)return json(res,400,{error:"Missing OAuth code or state"});
        const out=await githubCallback(pool,code,state);
        cookie(res,"dd_session",out.session,2592000);
        return res.writeHead(302,{Location:FRONTEND_URL}).end();
      }

      if(req.method==="POST"&&path==="/api/auth/exchange"){
        const d=await body(req);
        if(!d.code)return json(res,400,{error:"code is required"});
        const q=await pool.query("DELETE FROM oauth_handoffs WHERE code=$1 AND expires_at>now() RETURNING token_hash",[String(d.code)]);
        if(!q.rowCount)return json(res,400,{error:"Invalid or expired OAuth code"});
        const token=crypto.randomBytes(32).toString("base64url");
        const s=await pool.query("SELECT s.user_id,u.plan,u.github_login,u.github_email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()",[q.rows[0].token_hash]);
        if(!s.rowCount)return json(res,400,{error:"Session expired"});
        await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 days')",[hash(token),s.rows[0].user_id]);
        cookie(res,"dd_session",token,2592000);
        return json(res,200,{userId:s.rows[0].user_id,plan:s.rows[0].plan,githubLogin:s.rows[0].github_login,email:s.rows[0].github_email});
      }

      if(req.method==="POST"&&path==="/api/auth/anonymous"){
        const id=crypto.randomUUID(),token=crypto.randomBytes(32).toString("base64url");
        await pool.query("INSERT INTO users(id) VALUES($1)",[id]);
        await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 days')",[hash(token),id]);
        cookie(res,"dd_session",token,2592000);
        return json(res,201,{userId:id,plan:"free"});
      }

      if(req.method==="POST"&&path==="/api/auth/logout"){
        const token=authToken(req);
        if(token&&pool)await pool.query("DELETE FROM sessions WHERE token_hash=$1",[hash(token)]);
        clearCookie(res,"dd_session");
        return json(res,200,{ok:true});
      }

      const u=await user(req);
      if(!u)return json(res,401,{error:"Authentication required"});

      if(req.method==="GET"&&path==="/api/me")return json(res,200,{userId:u.user_id,plan:u.plan,githubConnected:!!u.github_access_token,githubLogin:u.github_login||null,email:u.github_email||null});

      if(req.method==="GET"&&path==="/api/github/repos"){
        if(!u.github_access_token)return json(res,400,{error:"GitHub account not connected"});
        const repos=await githubJson("https://api.github.com/user/repos?per_page=100&sort=updated",u.github_access_token);
        return json(res,200,{items:repos.map(r=>({id:r.id,fullName:r.full_name,name:r.name,owner:r.owner.login,defaultBranch:r.default_branch,private:r.private,url:r.html_url}))});
      }

      if(req.method==="POST"&&path==="/api/github/scan"){
        if(!u.github_access_token)return json(res,400,{error:"GitHub account not connected"});
        if(await usageCount(u.user_id)>=FREE_LIMIT)return json(res,429,{error:"Daily free limit reached",limit:FREE_LIMIT});
        const d=await body(req);
        if(!d.owner||!d.repo)return json(res,400,{error:"owner and repo are required"});
        const result=await scanGithubRepo({owner:String(d.owner),repo:String(d.repo),branch:d.branch,token:u.github_access_token,analyze});
        await pool.query("INSERT INTO analyses(user_id,tool,input,result) VALUES($1,$2,$3,$4)",[u.user_id,"github",String(d.owner)+"/"+String(d.repo),result]);
        return json(res,200,result);
      }

      if(req.method==="GET"&&path==="/api/usage")return json(res,200,{analyses:await usageCount(u.user_id),limit:FREE_LIMIT});

      if(req.method==="GET"&&path==="/api/history"){
        const r=await pool.query("SELECT id,tool,result,created_at FROM analyses WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50",[u.user_id]);
        return json(res,200,{items:r.rows});
      }

      if(req.method==="POST"&&path==="/api/analyze"){
        if(await usageCount(u.user_id)>=FREE_LIMIT)return json(res,429,{error:"Daily free limit reached",limit:FREE_LIMIT});
        const d=await body(req),tool=String(d.tool||"developer"),input=String(d.input||"");
        const result=analyze(tool,input);
        await pool.query("INSERT INTO analyses(user_id,tool,input,result) VALUES($1,$2,$3,$4)",[u.user_id,tool,input,result]);
        return json(res,200,{tool,result});
      }

      return json(res,404,{error:"Not found"});
    }catch(e){
      console.error(e);
      return json(res,500,{error:"Internal server error"});
    }
  });
  server.listen(process.env.PORT||3000,"0.0.0.0");
}
main().catch(e=>{console.error(e);process.exit(1)});