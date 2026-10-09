const { spawn } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const { createReadStream } = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function hashFile(file) {
  return new Promise((resolve,reject)=>{
    const hash=createHash("sha256");
    const stream=createReadStream(file);
    stream.on("data",chunk=>hash.update(chunk));
    stream.on("error",reject);
    stream.on("end",()=>resolve(hash.digest("hex")));
  });
}

function run(command,args,options={}) {
  return new Promise((resolve,reject)=>{
    const child=spawn(command,args,{stdio:["ignore","pipe","pipe"],...options});
    let stdout="",stderr="";
    child.stdout.on("data",chunk=>{stdout+=chunk.toString()});
    child.stderr.on("data",chunk=>{stderr+=chunk.toString()});
    child.on("error",reject);
    child.on("close",code=>code===0?resolve({stdout,stderr}):reject(new Error(command+" failed ("+code+"): "+stderr.slice(-2000))));
  });
}

async function main() {
  const databaseUrl=process.env.DATABASE_URL;
  const s3Prefix=process.env.BACKUP_S3_URI;
  const uploadUrl=process.env.BACKUP_UPLOAD_URL;
  if(!databaseUrl||(!s3Prefix&&!uploadUrl))throw new Error("Set DATABASE_URL and either BACKUP_S3_URI (recommended) or BACKUP_UPLOAD_URL.");
  if(uploadUrl&&!/^https:\/\//i.test(uploadUrl))throw new Error("BACKUP_UPLOAD_URL must use HTTPS.");
  if(s3Prefix&&!/^s3:\/\/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](?:\/.*)?$/i.test(s3Prefix))throw new Error("BACKUP_S3_URI must be an S3 bucket/prefix URI.");
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"developer-doctor-backup-"));
  const file=path.join(dir,"developer-doctor.dump");
  try{
    await run("pg_dump",[databaseUrl,"--format=custom","--no-owner","--no-acl","--file",file]);
    const stat=fs.statSync(file);
    if(stat.size<100)throw new Error("pg_dump produced an unexpectedly small backup.");
    const digest=await hashFile(file);
    const stamp=new Date().toISOString().replace(/[:.]/g,"-");
    if(s3Prefix){
      const target=s3Prefix.replace(/\/+$/,"")+"/developer-doctor-"+stamp+".dump";
      await run("aws",["s3","cp",file,target,"--only-show-errors","--sse","AES256","--metadata","sha256="+digest]);
      console.log(JSON.stringify({event:"backup_complete",destination:target,bytes:stat.size,sha256:digest,at:new Date().toISOString()}));
    }else{
      const response=await fetch(uploadUrl,{method:"PUT",body:fs.createReadStream(file),duplex:"half"});
      if(!response.ok)throw new Error("Offsite backup upload failed with HTTP "+response.status);
      console.log(JSON.stringify({event:"backup_complete",destination:"presigned-upload",bytes:stat.size,sha256:digest,at:new Date().toISOString()}));
    }
  }finally{fs.rmSync(dir,{recursive:true,force:true})}
}
main().catch(error=>{console.error(JSON.stringify({event:"backup_failed",message:error.message}));process.exitCode=1});
