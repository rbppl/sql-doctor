import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";

const port=process.env.TEST_PORT||"3107";
const child=spawn(process.execPath,["server.js"],{env:{...process.env,PORT:port,DATABASE_URL:""},stdio:["ignore","pipe","pipe"]});

try{
  const started=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error("server did not start in time")),5000);
    child.stdout.on("data",data=>{if(String(data).includes("listening")){clearTimeout(timer);resolve()}});
    child.stderr.on("data",data=>process.stderr.write(data));
  }).catch(async()=>{
    for(let i=0;i<25;i++){
      try{const r=await fetch(`http://127.0.0.1:${port}/health`);if(r.status===503){clearTimeout(timer);return}}catch{}
      await new Promise(r=>setTimeout(r,100));
    }
    throw new Error("server did not become reachable");
  });
  await started;
  const health=await fetch(`http://127.0.0.1:${port}/health`);
  assert.equal(health.status,503);
  const json=await health.json();
  assert.equal(json.ok,false);
  assert.equal(json.database,false);
  const badOrigin=await fetch(`http://127.0.0.1:${port}/health`,{headers:{Origin:"https://evil.example"}});
  assert.equal(badOrigin.status,403);
  console.log("backend smoke tests passed");
}finally{
  child.kill("SIGTERM");
  await new Promise(resolve=>child.once("exit",resolve));
}