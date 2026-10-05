const crypto=require("crypto");

function b64(value){return Buffer.from(value).toString("base64url");}
function appConfigured(){return !!(process.env.GITHUB_APP_ID&&process.env.GITHUB_APP_PRIVATE_KEY);}
function privateKey(){return String(process.env.GITHUB_APP_PRIVATE_KEY||"").replace(/\\n/g,"\n");}

function appJwt(){
  if(!appConfigured())throw new Error("GitHub App is not configured");
  const now=Math.floor(Date.now()/1000);
  const header=b64(JSON.stringify({alg:"RS256",typ:"JWT"}));
  const payload=b64(JSON.stringify({iat:now-60,exp:now+540,iss:String(process.env.GITHUB_APP_ID)}));
  const unsigned=header+"."+payload;
  const signature=crypto.sign("RSA-SHA256",Buffer.from(unsigned),privateKey());
  return unsigned+"."+signature.toString("base64url");
}

async function installationToken(installationId){
  if(!/^\d+$/.test(String(installationId)))throw new Error("Invalid GitHub installation id");
  const r=await fetch("https://api.github.com/app/installations/"+installationId+"/access_tokens",{
    method:"POST",
    headers:{
      Accept:"application/vnd.github+json",
      "X-GitHub-Api-Version":"2022-11-28",
      "User-Agent":"Developer-Doctor-GitHub-App",
      Authorization:"Bearer "+appJwt()
    }
  });
  if(!r.ok)throw new Error("GitHub installation token API "+r.status);
  const out=await r.json();
  if(!out.token)throw new Error("GitHub did not return an installation token");
  return out.token;
}

function verifyWebhook(rawBody,signature){
  const secret=process.env.GITHUB_APP_WEBHOOK_SECRET;
  if(!secret||!signature||!signature.startsWith("sha256="))return false;
  const expected="sha256="+crypto.createHmac("sha256",secret).update(rawBody).digest("hex");
  const a=Buffer.from(expected),b=Buffer.from(signature);
  return a.length===b.length&&crypto.timingSafeEqual(a,b);
}

async function checkRequest(url,token,method,body){
  const r=await fetch(url,{
    method,
    headers:{
      Accept:"application/vnd.github+json",
      "X-GitHub-Api-Version":"2022-11-28",
      "User-Agent":"Developer-Doctor-GitHub-App",
      Authorization:"Bearer "+token,
      "Content-Type":"application/json"
    },
    body:JSON.stringify(body)
  });
  if(!r.ok)throw new Error("GitHub check run API "+r.status);
  return r.json();
}

async function createCheckRun({token,owner,repo,headSha,status="queued",conclusion=null,summary="Developer Doctor is analyzing this pull request.",text=""}){
  return checkRequest(
    "https://api.github.com/repos/"+encodeURIComponent(owner)+"/"+encodeURIComponent(repo)+"/check-runs",
    token,"POST",
    {name:"Developer Doctor",head_sha:headSha,status,...(conclusion?{conclusion}:{}),output:{title:"Developer Doctor",summary,text}}
  );
}

async function updateCheckRun({token,owner,repo,checkRunId,conclusion,summary,text=""}){
  return checkRequest(
    "https://api.github.com/repos/"+encodeURIComponent(owner)+"/"+encodeURIComponent(repo)+"/check-runs/"+checkRunId,
    token,"PATCH",
    {status:"completed",conclusion,completed_at:new Date().toISOString(),output:{title:"Developer Doctor",summary,text}}
  );
}

module.exports={appConfigured,installationToken,verifyWebhook,createCheckRun,updateCheckRun};