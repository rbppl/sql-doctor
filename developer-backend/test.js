import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";

const port=process.env.TEST_PORT||"3107";
const child=spawn(process.execPath,["server.js"],{env:{...process.env,PORT:port,DATABASE_URL:""},stdio:["ignore","pipe","pipe"]});

try{
  let output="";
  child.stdout.on("data",data=>{output+=String(data)});
  child.stderr.on("data",data=>process.stderr.write(data));

  let ready=false;
  for(let i=0;i<50;i++){
    try{
      const r=await fetch(`http://127.0.0.1:${port}/health`);
      if(r.status===503){ready=true;break}
    }catch{}
    await new Promise(r=>setTimeout(r,100));
  }
  if(!ready)throw new Error(`server did not become reachable${output?`: ${output}`:""}`);

  const health=await fetch(`http://127.0.0.1:${port}/health`);
  assert.equal(health.status,503);
  const json=await health.json();
  assert.equal(json.ok,false);
  assert.equal(json.database,false);

  const badOrigin=await fetch(`http://127.0.0.1:${port}/health`,{headers:{Origin:"https://evil.example"}});
  assert.equal(badOrigin.status,403);

  const allowedOrigin=await fetch(`http://127.0.0.1:${port}/health`,{headers:{Origin:"https://developer-doctor-frontend.onrender.com"}});
  assert.equal(allowedOrigin.status,503);
  assert.equal(allowedOrigin.headers.get("access-control-allow-origin"),"https://developer-doctor-frontend.onrender.com");

  console.log("backend smoke tests passed");
}finally{
  child.kill("SIGTERM");
  await new Promise(resolve=>child.once("exit",resolve));
}