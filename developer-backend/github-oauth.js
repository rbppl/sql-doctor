const crypto=require("crypto");
const{encryptToken}=require("./github-crypto");

async function githubJson(url,token,options={}){
  const r=await fetch(url,{...options,headers:{Accept:"application/vnd.github+json","User-Agent":"Developer-Doctor",...(token?{Authorization:"Bearer "+token}:{})}});
  if(!r.ok)throw new Error("GitHub API "+r.status);
  return r.json();
}

async function githubLogin(pool){
  const state=crypto.randomBytes(32).toString("base64url");
  await pool.query("DELETE FROM oauth_states WHERE expires_at<=now()");
  await pool.query("INSERT INTO oauth_states(state,expires_at) VALUES($1,now()+interval '10 minutes')",[state]);
  const scope=process.env.GITHUB_OAUTH_SCOPE||"read:user user:email";
  const p=new URLSearchParams({client_id:process.env.GITHUB_CLIENT_ID,redirect_uri:process.env.GITHUB_CALLBACK_URL,scope,state});
  return {url:"https://github.com/login/oauth/authorize?"+p.toString(),state};
}

async function githubCallback(pool,code,state){
  if(!code||!state)throw new Error("Missing OAuth code or state");
  const q=await pool.query("DELETE FROM oauth_states WHERE state=$1 AND expires_at>now() RETURNING state",[state]);
  if(!q.rowCount)throw new Error("Invalid or expired OAuth state");

  const body=new URLSearchParams({client_id:process.env.GITHUB_CLIENT_ID,client_secret:process.env.GITHUB_CLIENT_SECRET,code});
  const tokenRes=await fetch("https://github.com/login/oauth/access_token",{method:"POST",headers:{"Accept":"application/json","User-Agent":"Developer-Doctor"},body});
  if(!tokenRes.ok)throw new Error("GitHub token exchange failed");
  const td=await tokenRes.json();
  if(!td.access_token)throw new Error("GitHub did not return an access token");

  const gh=await githubJson("https://api.github.com/user",td.access_token);
  let email=gh.email||null;
  if(!email){
    const emails=await githubJson("https://api.github.com/user/emails",td.access_token).catch(()=>[]);
    email=Array.isArray(emails)?(emails.find(item=>item.primary&&item.verified)?.email||null):null;
  }
  const encryptedToken=encryptToken(td.access_token);
  const up=await pool.query("SELECT id FROM users WHERE github_id=$1",[String(gh.id)]);
  let id;
  if(up.rowCount){
    id=up.rows[0].id;
    await pool.query("UPDATE users SET github_login=$1,github_email=$2,github_access_token=$3 WHERE id=$4",[gh.login,email,encryptedToken,id]);
  }else{
    id=crypto.randomUUID();
    await pool.query("INSERT INTO users(id,github_id,github_login,github_email,github_access_token) VALUES($1,$2,$3,$4,$5)",[id,String(gh.id),gh.login,email,encryptedToken]);
  }

  const handoff=crypto.randomBytes(32).toString("base64url");
  await pool.query("INSERT INTO oauth_handoffs(code,token_hash,user_id,expires_at) VALUES($1,NULL,$2,now()+interval '2 minutes')",[handoff,id]);
  return {code:handoff,userId:id,githubLogin:gh.login,email};
}

module.exports={githubLogin,githubCallback,githubJson};