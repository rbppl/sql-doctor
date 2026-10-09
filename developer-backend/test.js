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
  assert.equal(allowedOrigin.headers.get("x-content-type-options"),"nosniff");
  assert.equal(allowedOrigin.headers.get("cache-control"),"no-store");

  const preflight=await fetch(`http://127.0.0.1:${port}/api/analyze`,{
    method:"OPTIONS",
    headers:{
      Origin:"https://developer-doctor-frontend.onrender.com",
      "Access-Control-Request-Method":"POST",
      "Access-Control-Request-Headers":"content-type"
    }
  });
  assert.equal(preflight.status,204);
  assert.equal(preflight.headers.get("access-control-allow-origin"),"https://developer-doctor-frontend.onrender.com");

  const deniedPreflight=await fetch(`http://127.0.0.1:${port}/api/analyze`,{
    method:"OPTIONS",
    headers:{Origin:"https://evil.example","Access-Control-Request-Method":"POST"}
  });
  assert.equal(deniedPreflight.status,403);

  const unauthenticated=await fetch(`http://127.0.0.1:${port}/api/me`);
  assert.equal(unauthenticated.status,401);
  assert.equal((await unauthenticated.json()).error,"Authentication required");

  
// GitHub token encryption must round-trip and reject modified ciphertext.
const { encryptToken, decryptToken } = await import("./github-crypto.js").then(module => module.default || module);
const previousSecret = process.env.GITHUB_CLIENT_SECRET;
const previousEncryptionKey = process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
process.env.GITHUB_CLIENT_SECRET = "test-only-github-token-encryption-secret";
delete process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
try {
  const plaintext = "gho_test_token_do_not_use";
  const encryptedV1 = encryptToken(plaintext);
  assert.notEqual(encryptedV1, plaintext);
  assert.ok(encryptedV1.startsWith("enc:v1:"));
  assert.equal(decryptToken(encryptedV1), plaintext);
  const parts = encryptedV1.split(":");
  parts[3] = (parts[3][0] === "A" ? "B" : "A") + parts[3].slice(1);
  assert.throws(() => decryptToken(parts.join(":")));

  process.env.GITHUB_TOKEN_ENCRYPTION_KEY = "test-only-dedicated-encryption-key";
  const encryptedV2 = encryptToken(plaintext);
  assert.ok(encryptedV2.startsWith("enc:v2:"));
  assert.equal(decryptToken(encryptedV2), plaintext);
  const v2Parts = encryptedV2.split(":");
  v2Parts[3] = (v2Parts[3][0] === "A" ? "B" : "A") + v2Parts[3].slice(1);
  assert.throws(() => decryptToken(v2Parts.join(":")));
  delete process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
  assert.equal(decryptToken(encryptedV1), plaintext);
} finally {
  if (previousSecret === undefined) delete process.env.GITHUB_CLIENT_SECRET;
  else process.env.GITHUB_CLIENT_SECRET = previousSecret;
  if (previousEncryptionKey === undefined) delete process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
  else process.env.GITHUB_TOKEN_ENCRYPTION_KEY = previousEncryptionKey;
}

console.log("backend smoke tests passed");
}finally{
  child.kill("SIGTERM");
  await new Promise(resolve=>child.once("exit",resolve));
}