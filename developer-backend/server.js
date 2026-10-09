const http=require("http");
const crypto=require("crypto");
const{Pool}=require("pg");
const{scanGithubRepo}=require("./github-scanner");
const{githubLogin,githubCallback,githubJson}=require("./github-oauth");
const{encryptToken,decryptToken}=require("./github-crypto");
const{analyze}=require("./analyzers");
const{appConfigured,installationToken,verifyWebhook,createCheckRun,updateCheckRun}=require("./github-app");

const pool=process.env.DATABASE_URL?new Pool({
  connectionString:process.env.DATABASE_URL,
  ssl:process.env.DATABASE_URL.includes("render.com")?{rejectUnauthorized:false}:undefined
}):null;
const FREE_LIMIT=20;
const FRONTEND_URL=(process.env.FRONTEND_URL||"https://developer-doctor-frontend.onrender.com").replace(/\/$/,"");
const RATE_WINDOW_MS=60000;
const RATE_LIMIT=120;
const rateBuckets=new Map();
const runningPrChecks=new Set();


async function init(){
  if(!pool)return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,created_at TIMESTAMPTZ DEFAULT now(),plan TEXT NOT NULL DEFAULT 'free');
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at TIMESTAMPTZ DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL);
    CREATE TABLE IF NOT EXISTS analyses(id BIGSERIAL PRIMARY KEY,user_id TEXT NOT NULL,tool TEXT NOT NULL,input TEXT NOT NULL,result JSONB NOT NULL,created_at TIMESTAMPTZ DEFAULT now());
    CREATE INDEX IF NOT EXISTS analyses_user_created_idx ON analyses(user_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS daily_usage(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,usage_date DATE NOT NULL DEFAULT CURRENT_DATE,count INTEGER NOT NULL DEFAULT 0 CHECK(count>=0),PRIMARY KEY(user_id,usage_date));
    INSERT INTO daily_usage(user_id,usage_date,count)
      SELECT user_id,CURRENT_DATE,count(*)::int FROM analyses WHERE created_at>=date_trunc('day',now()) GROUP BY user_id
      ON CONFLICT(user_id,usage_date) DO UPDATE SET count=GREATEST(daily_usage.count,EXCLUDED.count);
    CREATE TABLE IF NOT EXISTS oauth_states(state TEXT PRIMARY KEY,created_at TIMESTAMPTZ DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL);
    CREATE TABLE IF NOT EXISTS oauth_handoffs(code TEXT PRIMARY KEY,token_hash TEXT, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,created_at TIMESTAMPTZ DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL);
    ALTER TABLE oauth_handoffs ALTER COLUMN token_hash DROP NOT NULL;
    ALTER TABLE oauth_handoffs ADD COLUMN IF NOT EXISTS user_id TEXT REFERENCES users(id) ON DELETE CASCADE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS github_id TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS github_login TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS github_email TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS github_access_token TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS users_github_id_idx ON users(github_id) WHERE github_id IS NOT NULL;
  `);
  if(process.env.GITHUB_CLIENT_SECRET||process.env.GITHUB_TOKEN_ENCRYPTION_KEY){
    const legacy=process.env.GITHUB_TOKEN_ENCRYPTION_KEY
      ? await pool.query("SELECT id,github_access_token FROM users WHERE github_access_token IS NOT NULL AND github_access_token NOT LIKE $1",["enc:v2:%"])
      : await pool.query("SELECT id,github_access_token FROM users WHERE github_access_token IS NOT NULL AND github_access_token NOT LIKE $1",["enc:v1:%"]);
    for(const row of legacy.rows){
      const plaintext=decryptToken(row.github_access_token);
      await pool.query("UPDATE users SET github_access_token=$1 WHERE id=$2",[encryptToken(plaintext),row.id]);
    }
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

function appendCookie(res,value){
  const previous=res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie",previous?[...(Array.isArray(previous)?previous:[previous]),value]:[value]);
}
function cookie(res,name,value,maxAge,sameSite="None"){
  appendCookie(res,`${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=${sameSite}`);
}
function clearCookie(res,name,sameSite="None"){
  appendCookie(res,`${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=${sameSite}`);
}
function cookieValue(req,name){
  const prefix=name+"=";
  const entry=String(req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(prefix));
  if(!entry)return null;
  try{return decodeURIComponent(entry.slice(prefix.length))}catch{return null}
}

function authToken(req){
  const bearer=String(req.headers.authorization||"").match(/^Bearer\s+(.+)$/i);
  if(bearer)return bearer[1];
  return cookieValue(req,"dd_session");
}

async function user(req){
  const token=authToken(req);
  if(!pool||!token)return null;
  const r=await pool.query(
    "SELECT s.user_id,u.plan,u.github_access_token,u.github_login,u.github_email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()",
    [hash(token)]
  );
  if(!r.rowCount)return null;
  if(r.rows[0].github_access_token)r.rows[0].github_access_token=decryptToken(r.rows[0].github_access_token);
  return r.rows[0];
}

function rateKey(req){
  const token=authToken(req);
  return token?"session:"+hash(token):"ip:"+(req.socket.remoteAddress||"unknown");
}
function rateAllowed(req){
  const now=Date.now(),key=rateKey(req);
  const bucket=rateBuckets.get(key);
  if(!bucket||now>=bucket.reset){rateBuckets.set(key,{count:1,reset:now+RATE_WINDOW_MS});return true}
  if(bucket.count>=RATE_LIMIT)return false;
  bucket.count++;
  return true;
}
setInterval(()=>{const now=Date.now();for(const [key,b] of rateBuckets)if(now>=b.reset)rateBuckets.delete(key)},RATE_WINDOW_MS).unref();

async function usageCount(id){
  const r=await pool.query("SELECT COALESCE((SELECT count FROM daily_usage WHERE user_id=$1 AND usage_date=CURRENT_DATE),(SELECT count(*)::int FROM analyses WHERE user_id=$1 AND created_at>=date_trunc('day',now()))) AS n",[id]);
  return Number(r.rows[0].n)||0;
}
async function reserveUsage(id){
  const r=await pool.query("INSERT INTO daily_usage(user_id,usage_date,count) VALUES($1,CURRENT_DATE,1) ON CONFLICT(user_id,usage_date) DO UPDATE SET count=daily_usage.count+1 WHERE daily_usage.count<$2 RETURNING count",[id,FREE_LIMIT]);
  return r.rowCount===1;
}
async function releaseUsage(id){
  await pool.query("UPDATE daily_usage SET count=GREATEST(0,count-1) WHERE user_id=$1 AND usage_date=CURRENT_DATE",[id]);
}

function body(req){
  return new Promise((resolve,reject)=>{
    let s="";
    let settled=false;
    req.on("data",c=>{
      if(settled)return;
      s+=c;
      if(Buffer.byteLength(s,"utf8")>100000){settled=true;reject(Object.assign(new Error("Request too large"),{statusCode:413}));req.resume()}
    });
    req.on("end",()=>{
      if(settled)return;
      try{resolve(JSON.parse(s||"{}"))}catch(e){reject(Object.assign(new Error("Invalid JSON body"),{statusCode:400}))}
    });
    req.on("error",reject);
  });
}


async function rawBody(req,maxBytes=1000000){
  return new Promise((resolve,reject)=>{
    const chunks=[];let size=0;
    let settled=false;
    req.on("data",chunk=>{if(settled)return;size+=chunk.length;if(size>maxBytes){settled=true;reject(Object.assign(new Error("Request too large"),{statusCode:413}));req.resume();return}chunks.push(chunk)});
    req.on("end",()=>{if(!settled)resolve(Buffer.concat(chunks))});
    req.on("error",reject);
  });
}
function webhookSummary(result){
  const counts={critical:0,high:0,medium:0,low:0};
  for(const issue of result.issues||[])counts[issue.severity]=(counts[issue.severity]||0)+1;
  return {counts,total:result.issues?.length||0};
}
async function runPullRequestCheck(payload,token,checkRunId){
  const repo=payload.repository?.full_name;
  const [owner,name]=String(repo||"").split("/");
  const number=Number(payload.number);
  const sha=payload.pull_request?.head?.sha;
  if(!owner||!name||!Number.isInteger(number)||!sha)return;
  const key=repo+"#"+number+"@"+sha;
  if(runningPrChecks.has(key))return;
  runningPrChecks.add(key);
  try{
    const result=await scanGithubRepo({owner,repo:name,branch:"refs/pull/"+number+"/head",token,analyze});
    const {counts,total}=webhookSummary(result);
    const critical=(counts.critical||0)+(counts.high||0);
    const conclusion=critical>0?"failure":"success";
    const summary=total===0?"No supported issues found in this pull request.":total+" issue"+(total===1?"":"s")+" found. "+(counts.high||0)+" high/critical.";
    const text=[
      "Score: "+result.score+"/100",
      "Files scanned: "+result.filesScanned,
      "",
      ...(result.issues||[]).slice(0,30).map(x=>String(x.severity).toUpperCase()+" "+x.file+" — "+x.message+(x.fix?" Fix: "+x.fix:""))
    ].join("\n");
    await updateCheckRun({token,owner,repo:name,checkRunId,conclusion,summary,text});
  }catch(error){
    console.error("PR check failed",error);
    await updateCheckRun({token,owner,repo:name,checkRunId,conclusion:"failure",summary:"Developer Doctor could not complete the analysis.",text:String(error.message||error)}).catch(e=>console.error("Failed to update PR check",e));
  }finally{runningPrChecks.delete(key)}
}

async function main(){
  await init();
  const server=http.createServer(async(req,res)=>{
    let reservedUserId=null;
    try{
      const url=new URL(req.url,"http://localhost"),path=url.pathname,origin=req.headers.origin;
      if(req.method==="OPTIONS"){
        if(!originAllowed(origin))return json(res,403,{error:"Origin not allowed"});
        return json(res,204,{});
      }
      if(!originAllowed(origin))return json(res,403,{error:"Origin not allowed"});

      if(!(req.method==="GET"&&(path==="/"||path==="/health"))&&!rateAllowed(req)){
        res.setHeader("Retry-After","60");
        return json(res,429,{error:"Rate limit exceeded",retryAfter:60});
      }

      if(req.method==="GET"&&(path==="/"||path==="/health")){
        let database=true;
        if(pool){
          try{await pool.query("SELECT 1")}catch(e){database=false}
        }else database=false;
        return json(res,database?200:503,{ok:database,database,service:"developer-doctor-backend"});
      }


      if(req.method==="POST"&&path==="/api/github/webhook"){
        if(!appConfigured())return json(res,503,{error:"GitHub App is not configured"});
        const raw=await rawBody(req);
        if(!verifyWebhook(raw,req.headers["x-hub-signature-256"]))return json(res,401,{error:"Invalid webhook signature"});
        let payload;try{payload=JSON.parse(raw.toString("utf8"))}catch{return json(res,400,{error:"Invalid webhook JSON"})}
        const event=String(req.headers["x-github-event"]||"");
        if(event!=="pull_request")return json(res,202,{ok:true,ignored:true,event});
        const action=String(payload.action||"");
        if(!["opened","reopened","synchronize"].includes(action))return json(res,202,{ok:true,ignored:true,action});
        const installationId=payload.installation?.id;
        if(!installationId)return json(res,400,{error:"Missing GitHub installation"});
        const repo=payload.repository?.full_name,sha=payload.pull_request?.head?.sha;
        if(!repo||!sha)return json(res,400,{error:"Missing pull request repository or SHA"});
        const [owner,name]=String(repo).split("/");
        const token=await installationToken(installationId);
        const check=await createCheckRun({token,owner,repo:name,headSha:sha,status:"in_progress",summary:"Developer Doctor is analyzing this pull request."});
        setImmediate(()=>runPullRequestCheck(payload,token,check.id));
        return json(res,202,{ok:true,checkRunId:check.id});
      }

      if(req.method==="GET"&&path==="/api/auth/github"){
        if(!pool||!process.env.GITHUB_CLIENT_ID||!process.env.GITHUB_CLIENT_SECRET||!process.env.GITHUB_CALLBACK_URL)return json(res,503,{error:"GitHub OAuth is not configured"});
        const auth=await githubLogin(pool);
        cookie(res,"dd_oauth_state",auth.state,600,"Lax");
        return res.writeHead(302,{Location:auth.url}).end();
      }

      if(req.method==="GET"&&path==="/api/auth/github/callback"){
        const code=url.searchParams.get("code"),state=url.searchParams.get("state");
        const stateCookie=cookieValue(req,"dd_oauth_state");
        clearCookie(res,"dd_oauth_state", "Lax");
        if(!code||!state||!stateCookie||state!==stateCookie)return json(res,400,{error:"Invalid OAuth state. Please restart GitHub sign-in."});
        const out=await githubCallback(pool,code,state);
        return res.writeHead(302,{Location:FRONTEND_URL+"/?oauth_code="+encodeURIComponent(out.code),"cache-control":"no-store","referrer-policy":"no-referrer"}).end();
      }

      if(req.method==="POST"&&path==="/api/auth/exchange"){
        if(!pool)return json(res,503,{error:"Database unavailable"});
        const d=await body(req);
        const code=typeof d.code==="string"?d.code:"";
        if(!/^[A-Za-z0-9_-]{40,60}$/.test(code))return json(res,400,{error:"Valid OAuth code is required"});
        const q=await pool.query("DELETE FROM oauth_handoffs WHERE code=$1 AND expires_at>now() RETURNING user_id",[code]);
        if(!q.rowCount||!q.rows[0].user_id)return json(res,400,{error:"Invalid or expired OAuth code"});
        const token=crypto.randomBytes(32).toString("base64url");
        const s=await pool.query("SELECT id,plan,github_login,github_email FROM users WHERE id=$1",[q.rows[0].user_id]);
        if(!s.rowCount)return json(res,400,{error:"OAuth account no longer exists"});
        await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 days')",[hash(token),s.rows[0].id]);
        cookie(res,"dd_session",token,2592000);
        return json(res,200,{userId:s.rows[0].id,plan:s.rows[0].plan,githubLogin:s.rows[0].github_login,email:s.rows[0].github_email});
      }

      if(req.method==="POST"&&path==="/api/auth/anonymous"){
        if(!pool)return json(res,503,{error:"Database unavailable"});
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

      if(req.method==="GET"&&path==="/api/github/prs"){
        if(!u.github_access_token)return json(res,400,{error:"GitHub account not connected"});
        const owner=String(url.searchParams.get("owner")||"");
        const repo=String(url.searchParams.get("repo")||"");
        if(owner.length>100||repo.length>100||!/^[A-Za-z0-9_.-]+$/.test(owner)||!/^[A-Za-z0-9_.-]+$/.test(repo))return json(res,400,{error:"Valid owner and repo are required"});
        const prs=await githubJson("https://api.github.com/repos/"+owner+"/"+repo+"/pulls?state=open&per_page=30&sort=updated",u.github_access_token);
        return json(res,200,{items:prs.map(p=>({number:p.number,title:p.title,author:p.user?.login||"unknown",updatedAt:p.updated_at,headRepo:p.head?.repo?.full_name||null,headBranch:p.head?.ref||null,url:p.html_url}))});
      }

      if(req.method==="GET"&&path==="/api/github/repos"){
        if(!u.github_access_token)return json(res,400,{error:"GitHub account not connected"});
        const repos=await githubJson("https://api.github.com/user/repos?per_page=100&sort=updated",u.github_access_token);
        return json(res,200,{items:repos.map(r=>({id:r.id,fullName:r.full_name,name:r.name,owner:r.owner.login,defaultBranch:r.default_branch,private:r.private,url:r.html_url}))});
      }

      if(req.method==="POST"&&path==="/api/github/scan-pr"){
        if(!u.github_access_token)return json(res,400,{error:"GitHub account not connected"});
        const d=await body(req);
        const owner=String(d.owner||""),repo=String(d.repo||""),number=Number(d.number);
        if(owner.length>100||repo.length>100||! /^[A-Za-z0-9_.-]+$/.test(owner)||! /^[A-Za-z0-9_.-]+$/.test(repo)||!Number.isInteger(number)||number<1||number>2147483647)return json(res,400,{error:"Valid owner, repo and PR number are required"});
        const pr=await githubJson("https://api.github.com/repos/"+owner+"/"+repo+"/pulls/"+number,u.github_access_token);
        if(pr.state!=="open")return json(res,400,{error:"Only open pull requests can be scanned"});
        const sourceRepo=pr.head?.repo?.full_name;
        const sourceBranch=pr.head?.ref;
        if(!sourceRepo||!sourceBranch)return json(res,400,{error:"Pull request source repository is unavailable"});
        const [sourceOwner,sourceName]=sourceRepo.split("/");
        if(!await reserveUsage(u.user_id))return json(res,429,{error:"Daily free limit reached",limit:FREE_LIMIT});
        reservedUserId=u.user_id;
        const result=await scanGithubRepo({owner:sourceOwner,repo:sourceName,branch:sourceBranch,token:u.github_access_token,analyze});
        result.pullRequest={number,title:pr.title,url:pr.html_url,base:pr.base?.ref||null,head:sourceRepo+":"+sourceBranch};
        await pool.query("INSERT INTO analyses(user_id,tool,input,result) VALUES($1,$2,$3,$4)",[u.user_id,"github-pr",owner+"/"+repo+"#"+number,result]);
        reservedUserId=null;
        return json(res,200,result);
      }

      if(req.method==="POST"&&path==="/api/github/scan"){
        if(!u.github_access_token)return json(res,400,{error:"GitHub account not connected"});
        const d=await body(req);
        if(typeof d.owner!=="string"||typeof d.repo!=="string"||!d.owner||!d.repo)return json(res,400,{error:"owner and repo are required"});
        if(!/^[A-Za-z0-9_.-]+$/.test(d.owner)||!/^[A-Za-z0-9_.-]+$/.test(d.repo))return json(res,400,{error:"Invalid owner or repo"});
        if(!await reserveUsage(u.user_id))return json(res,429,{error:"Daily free limit reached",limit:FREE_LIMIT});
        reservedUserId=u.user_id;
        const result=await scanGithubRepo({owner:d.owner,repo:d.repo,branch:d.branch,token:u.github_access_token,analyze});
        await pool.query("INSERT INTO analyses(user_id,tool,input,result) VALUES($1,$2,$3,$4)",[u.user_id,"github",d.owner+"/"+d.repo,result]);
        reservedUserId=null;
        return json(res,200,result);
      }

      if(req.method==="GET"&&path==="/api/usage")return json(res,200,{analyses:await usageCount(u.user_id),limit:FREE_LIMIT});

      if(req.method==="GET"&&path==="/api/history"){
        const r=await pool.query("SELECT id,tool,result,created_at FROM analyses WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50",[u.user_id]);
        return json(res,200,{items:r.rows});
      }

      if(req.method==="POST"&&path==="/api/analyze"){
        const d=await body(req),tool=String(d.tool||"developer"),input=String(d.input||"");
        if(!["sql","json","api","git","docker","developer"].includes(tool))return json(res,400,{error:"Unsupported analysis tool"});
        if(Buffer.byteLength(input,"utf8")>90000)return json(res,413,{error:"Input exceeds 90 KB"});
        if(!await reserveUsage(u.user_id))return json(res,429,{error:"Daily free limit reached",limit:FREE_LIMIT});
        reservedUserId=u.user_id;
        const result=analyze(tool,input);
        await pool.query("INSERT INTO analyses(user_id,tool,input,result) VALUES($1,$2,$3,$4)",[u.user_id,tool,input,result]);
        reservedUserId=null;
        return json(res,200,{tool,result});
      }

      return json(res,404,{error:"Not found"});
    }catch(e){
      if(reservedUserId){await releaseUsage(reservedUserId).catch(()=>{});reservedUserId=null;}
      if(e?.statusCode===400||e?.statusCode===413){
        return json(res,e.statusCode,{error:e.message});
      }
      if(e?.code==="GITHUB_RATE_LIMIT"){
        const retryAfter=Number(e.retryAfter)||60;
        res.setHeader("Retry-After",String(retryAfter));
        return json(res,429,{error:"GitHub API rate limit reached",retryAfter});
      }
      if(e?.message==="GitHub API 401")return json(res,401,{error:"GitHub authorization expired. Reconnect GitHub and try again."});
      if(e?.message==="GitHub API 403")return json(res,403,{error:"GitHub denied access to this repository. Check repository permissions and OAuth scopes."});
      if(e?.message==="GitHub API 404")return json(res,404,{error:"Repository or resource not found, or your GitHub account cannot access it."});
      console.error("Unhandled request error",e?.message||e);
      return json(res,500,{error:"Internal server error"});
    }
  });
  server.listen(process.env.PORT||3000,"0.0.0.0");
}
main().catch(e=>{console.error(e);process.exit(1)});