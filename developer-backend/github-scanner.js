const IGNORE=/^(node_modules|\.git|dist|build|target|\.venv|vendor)\//;
const ALLOWED=/((^|\/)(Dockerfile[^/]*|docker-compose[^/]*\.ya?ml)|\.sql$|\.json$|\.ya?ml$)/i;
const REQUEST_TIMEOUT_MS=10000;
const MAX_FILES=100;
const MAX_FILE_BYTES=1000000;
const MAX_TOTAL_BYTES=5000000;
const MAX_CONCURRENCY=5;

async function githubJson(url,token){
  const r=await fetch(url,{signal:AbortSignal.timeout(REQUEST_TIMEOUT_MS),headers:{Authorization:"Bearer "+token,Accept:"application/vnd.github+json","User-Agent":"Developer-Doctor"}});
  if(!r.ok){
    if((r.status===403||r.status===429)&&r.headers.get("x-ratelimit-remaining")==="0"){
      const e=new Error("GitHub API rate limit reached");
      e.code="GITHUB_RATE_LIMIT";
      const reset=Number(r.headers.get("x-ratelimit-reset"));
      e.retryAfter=Number.isFinite(reset)?Math.max(1,reset-Math.floor(Date.now()/1000)):60;
      throw e;
    }
    throw new Error("GitHub API "+r.status);
  }
  return r.json();
}

async function scanGithubRepo({owner,repo,branch,token,analyze}){
  if(typeof owner!=="string"||typeof repo!=="string"||owner.length>100||repo.length>100||! /^[A-Za-z0-9_.-]+$/.test(owner)||! /^[A-Za-z0-9_.-]+$/.test(repo))throw new Error("Invalid repository");
  if(branch!==undefined&&branch!==null&&(typeof branch!=="string"||branch.length>255||/[\u0000-\u001f]/.test(branch)))throw new Error("Invalid branch");
  const ref=encodeURIComponent(branch||"HEAD");
  const tree=await githubJson("https://api.github.com/repos/"+owner+"/"+repo+"/git/trees/"+ref+"?recursive=1",token);
  if(tree.truncated)throw new Error("Repository tree is too large");
  const files=(tree.tree||[]).filter(x=>x.type==="blob"&&x.path.length<500&&!IGNORE.test(x.path)&&ALLOWED.test(x.path)).slice(0,MAX_FILES);
  const issues=[];let scanned=0,totalBytes=0,index=0;
  async function worker(){
    while(true){
      const i=index++;
      if(i>=files.length)return;
      const f=files[i];
      const encodedPath=f.path.split("/").map(encodeURIComponent).join("/");
      const data=await githubJson("https://api.github.com/repos/"+owner+"/"+repo+"/contents/"+encodedPath+"?ref="+ref,token);
      if(!Number.isFinite(data.size)||data.size<0||data.size>MAX_FILE_BYTES||!data.content)continue;
      if(totalBytes+data.size>MAX_TOTAL_BYTES)continue;
      const input=Buffer.from(data.content.replace(/\n/g,""),"base64").toString("utf8");
      const actualBytes=Buffer.byteLength(input,"utf8");
      if(actualBytes>MAX_FILE_BYTES||totalBytes+actualBytes>MAX_TOTAL_BYTES)continue;
      totalBytes+=actualBytes;
      const ext=f.path.toLowerCase();
      const tool=ext.endsWith(".sql")?"sql":ext.endsWith(".json")?"json":/dockerfile|docker-compose/.test(ext)?"docker":"api";
      const result=analyze(tool,input);
      for(const finding of result.findings||[])issues.push({file:f.path,tool,severity:finding.severity,message:finding.message,fix:finding.fix});
      scanned++;
    }
  }
  await Promise.all(Array.from({length:Math.min(MAX_CONCURRENCY,files.length)},worker));
  const score=Math.max(0,100-issues.reduce((n,x)=>n+(x.severity==="critical"?20:x.severity==="high"?12:x.severity==="medium"?6:2),0));
  return{score,filesScanned:scanned,filesConsidered:files.length,issues};
}
module.exports={scanGithubRepo};