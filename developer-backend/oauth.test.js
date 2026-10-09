import { strict as assert } from "node:assert";
const oauthModule = await import("./github-oauth.js");
const { githubLogin, githubCallback } = oauthModule.default || oauthModule;

const statements=[];
const pool={query:async(sql,params=[])=>{
  statements.push({sql,params});
  if(sql.startsWith("DELETE FROM oauth_states"))return {rowCount:0,rows:[]};
  if(sql.startsWith("INSERT INTO oauth_states"))return {rowCount:1,rows:[]};
  if(sql.startsWith("DELETE FROM oauth_states WHERE state="))return {rowCount:0,rows:[]};
  return {rowCount:0,rows:[]};
}};

const previous={
  id:process.env.GITHUB_CLIENT_ID,
  callback:process.env.GITHUB_CALLBACK_URL,
  scope:process.env.GITHUB_OAUTH_SCOPE
};
process.env.GITHUB_CLIENT_ID="test-client-id";
process.env.GITHUB_CALLBACK_URL="https://example.test/api/auth/github/callback";
delete process.env.GITHUB_OAUTH_SCOPE;
try {
  const login=await githubLogin(pool);
  const url=new URL(login.url);
  assert.equal(url.origin,"https://github.com");
  assert.equal(url.pathname,"/login/oauth/authorize");
  assert.equal(url.searchParams.get("client_id"),"test-client-id");
  assert.equal(url.searchParams.get("redirect_uri"),process.env.GITHUB_CALLBACK_URL);
  assert.equal(url.searchParams.get("scope"),"read:user user:email");
  assert.equal(url.searchParams.get("state"),login.state);
  assert.ok(login.state.length>=40);

  process.env.GITHUB_OAUTH_SCOPE="read:user user:email";
  const configurable=await githubLogin(pool);
  assert.equal(new URL(configurable.url).searchParams.get("scope"),process.env.GITHUB_OAUTH_SCOPE);

  await assert.rejects(githubCallback(pool,"fake-code","invalid-state"),/Invalid or expired OAuth state/);
  assert.ok(statements.some(s=>s.sql.startsWith("DELETE FROM oauth_states WHERE state=")));
  console.log("OAuth regression tests passed");
} finally {
  if(previous.id===undefined)delete process.env.GITHUB_CLIENT_ID;else process.env.GITHUB_CLIENT_ID=previous.id;
  if(previous.callback===undefined)delete process.env.GITHUB_CALLBACK_URL;else process.env.GITHUB_CALLBACK_URL=previous.callback;
  if(previous.scope===undefined)delete process.env.GITHUB_OAUTH_SCOPE;else process.env.GITHUB_OAUTH_SCOPE=previous.scope;
}
