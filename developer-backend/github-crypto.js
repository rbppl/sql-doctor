const crypto=require("crypto");

function key(secret){
  if(!secret)throw new Error("Token encryption key is not configured");
  return crypto.createHash("sha256").update("developer-doctor:github-token-encryption:").update(secret).digest();
}

function encryptToken(value){
  if(!value)return value;
  if(String(value).startsWith("enc:v1:")||String(value).startsWith("enc:v2:"))return value;
  const useDedicated=!!process.env.GITHUB_TOKEN_ENCRYPTION_KEY;
  const secret=useDedicated?process.env.GITHUB_TOKEN_ENCRYPTION_KEY:process.env.GITHUB_CLIENT_SECRET;
  if(!secret)throw new Error("GITHUB_TOKEN_ENCRYPTION_KEY or GITHUB_CLIENT_SECRET is required");
  const version=useDedicated?"v2":"v1";
  const iv=crypto.randomBytes(12);
  const cipher=crypto.createCipheriv("aes-256-gcm",key(secret),iv);
  const encrypted=Buffer.concat([cipher.update(String(value),"utf8"),cipher.final()]);
  const tag=cipher.getAuthTag();
  return "enc:"+version+":"+iv.toString("base64url")+":"+tag.toString("base64url")+":"+encrypted.toString("base64url");
}

function decryptToken(value){
  if(!value)return value;
  const text=String(value);
  if(!text.startsWith("enc:v1:")&&!text.startsWith("enc:v2:"))return text;
  const [,version,ivRaw,tagRaw,dataRaw]=text.split(":");
  if(!["v1","v2"].includes(version)||!ivRaw||!tagRaw||!dataRaw)throw new Error("Invalid encrypted GitHub token");
  const secret=version==="v2"?process.env.GITHUB_TOKEN_ENCRYPTION_KEY:process.env.GITHUB_CLIENT_SECRET;
  if(!secret)throw new Error("Encryption key for "+version+" is not configured");
  const iv=Buffer.from(ivRaw,"base64url"),tag=Buffer.from(tagRaw,"base64url"),data=Buffer.from(dataRaw,"base64url");
  if(iv.length!==12||tag.length!==16||data.length===0)throw new Error("Invalid encrypted GitHub token");
  const decipher=crypto.createDecipheriv("aes-256-gcm",key(secret),iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data),decipher.final()]).toString("utf8");
}

module.exports={encryptToken,decryptToken};
