const crypto=require("crypto");

function key(){
  const secret=process.env.GITHUB_CLIENT_SECRET;
  if(!secret)throw new Error("GITHUB_CLIENT_SECRET is required");
  return crypto.createHash("sha256").update("developer-doctor:github-token:v1:").update(secret).digest();
}

function encryptToken(value){
  if(!value)return value;
  if(String(value).startsWith("enc:v1:"))return value;
  const iv=crypto.randomBytes(12);
  const cipher=crypto.createCipheriv("aes-256-gcm",key(),iv);
  const encrypted=Buffer.concat([cipher.update(String(value),"utf8"),cipher.final()]);
  const tag=cipher.getAuthTag();
  return "enc:v1:"+iv.toString("base64url")+":"+tag.toString("base64url")+":"+encrypted.toString("base64url");
}

function decryptToken(value){
  if(!value)return value;
  if(!String(value).startsWith("enc:v1:"))return value;
  const [,version,ivRaw,tagRaw,dataRaw]=String(value).split(":");
  if(version!=="v1"||!ivRaw||!tagRaw||!dataRaw)throw new Error("Invalid encrypted GitHub token");
  const decipher=crypto.createDecipheriv("aes-256-gcm",key(),Buffer.from(ivRaw,"base64url"));
  decipher.setAuthTag(Buffer.from(tagRaw,"base64url"));
  return Buffer.concat([decipher.update(Buffer.from(dataRaw,"base64url")),decipher.final()]).toString("utf8");
}

module.exports={encryptToken,decryptToken};