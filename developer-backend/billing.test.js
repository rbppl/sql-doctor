const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const {verifyStripeSignature,createCheckout,createPortal}=require("./billing");

async function main(){
  const raw=Buffer.from(JSON.stringify({id:"evt_test",type:"checkout.session.completed"}));
  const secret="whsec_test_secret";
  const timestamp=1700000000;
  const signature=crypto.createHmac("sha256",secret).update(String(timestamp)+".").update(raw).digest("hex");
  assert.equal(verifyStripeSignature(raw,"t="+timestamp+",v1="+signature,secret,timestamp),true);
  assert.equal(verifyStripeSignature(raw,"t="+timestamp+",v1="+signature,"wrong",timestamp),false);
  assert.equal(verifyStripeSignature(raw,"t="+(timestamp-301)+",v1="+signature,secret,timestamp),false);
  assert.equal(verifyStripeSignature(raw,"t="+timestamp+",v1=bad",secret,timestamp),false);
  assert.equal(verifyStripeSignature(raw,"",secret,timestamp),false);

  const originalFetch=global.fetch;
  const requests=[];
  global.fetch=async(url,opts)=>{
    requests.push({url:String(url),opts});
    return {ok:true,json:async()=>({id:"cs_test",url:"https://checkout.stripe.test/session"})};
  };
  try{
    const checkout=await createCheckout({secret:"sk_test",priceId:"price_test",userId:"user-123",customerId:null,email:"person@example.test",frontendUrl:"https://app.example.test"});
    assert.equal(checkout.url,"https://checkout.stripe.test/session");
    const body=new URLSearchParams(requests[0].opts.body);
    assert.equal(body.get("mode"),"subscription");
    assert.equal(body.get("line_items[0][price]"),"price_test");
    assert.equal(body.get("metadata[user_id]"),"user-123");
    assert.equal(body.get("subscription_data[metadata][user_id]"),"user-123");
    assert.equal(body.get("customer_email"),"person@example.test");
    assert.ok(requests[0].opts.headers["idempotency-key"]);
    await createPortal({secret:"sk_test",customerId:"cus_test",frontendUrl:"https://app.example.test"});
    assert.equal(new URLSearchParams(requests[1].opts.body).get("customer"),"cus_test");
    await assert.rejects(createCheckout({secret:"sk_test",priceId:"",userId:"u",frontendUrl:"https://app.example.test"}),/STRIPE_PRICE_ID/);
    await assert.rejects(createPortal({secret:"sk_test",customerId:"",frontendUrl:"https://app.example.test"}),/No billing customer/);
  }finally{global.fetch=originalFetch}
  console.log("billing tests passed");
}
main().catch(e=>{console.error(e);process.exitCode=1});
