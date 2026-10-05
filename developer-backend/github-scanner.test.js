const assert=require("assert");
const {scanGithubRepo}=require("./github-scanner");
(async()=>{
  const result=await scanGithubRepo({
    owner:"rbppl",
    repo:"sql-doctor",
    branch:"main",
    token:process.env.GITHUB_TEST_TOKEN,
    analyze:(tool,input)=>{
      if(tool==="sql") return {score:100,findings:[]};
      if(tool==="json") return {score:100,findings:[]};
      if(tool==="docker") return {score:100,findings:[]};
      return {score:100,findings:[]};
    }
  });
  assert(Number.isInteger(result.filesScanned));
  assert(Array.isArray(result.issues));
  console.log(JSON.stringify({ok:true,score:result.score,filesScanned:result.filesScanned},null,2));
})().catch(e=>{console.error(e);process.exit(1)});