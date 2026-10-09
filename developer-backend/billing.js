const crypto = require("node:crypto");

function verifyStripeSignature(rawBody, signatureHeader, secret, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!secret || !Buffer.isBuffer(rawBody) || typeof signatureHeader !== "string") return false;
  const parts = signatureHeader.split(",").map(part => part.trim().split("="));
  const timestamp = parts.find(([key]) => key === "t")?.[1];
  const signatures = parts.filter(([key]) => key === "v1").map(([, value]) => value);
  if (!timestamp || !/^\d+$/.test(timestamp) || !signatures.length) return false;
  if (Math.abs(nowSeconds - Number(timestamp)) > 300) return false;
  const expected = crypto.createHmac("sha256", secret).update(timestamp + ".").update(rawBody).digest("hex");
  const expectedBuffer = Buffer.from(expected, "hex");
  return signatures.some(value => {
    if (!/^[a-f0-9]{64}$/i.test(value)) return false;
    const actual = Buffer.from(value, "hex");
    return actual.length === expectedBuffer.length && crypto.timingSafeEqual(actual, expectedBuffer);
  });
}

async function stripeRequest(path, secret, params, idempotencyKey) {
  if (!secret) throw new Error("Stripe billing is not configured");
  const response = await fetch("https://api.stripe.com/v1/" + path, {
    method: "POST",
    headers: {
      authorization: "Bearer " + secret,
      "content-type": "application/x-www-form-urlencoded",
      ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {})
    },
    body: new URLSearchParams(params)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data?.error?.message || "Stripe request failed");
    error.statusCode = response.status >= 500 ? 502 : 400;
    throw error;
  }
  return data;
}

async function createCheckout({ secret, priceId, userId, customerId, email, frontendUrl }) {
  if (!priceId) throw new Error("STRIPE_PRICE_ID is not configured");
  const params = {
    mode: "subscription",
    "line_items[0][price]": priceId,
    "line_items[0][quantity]": "1",
    success_url: frontendUrl + "/?billing=success",
    cancel_url: frontendUrl + "/?billing=cancelled",
    client_reference_id: userId,
    "metadata[user_id]": userId,
    "subscription_data[metadata][user_id]": userId,
    "allow_promotion_codes": "true"
  };
  if (customerId) params.customer = customerId;
  else if (email) params.customer_email = email;
  return stripeRequest("checkout/sessions", secret, params, "checkout-" + userId + "-" + crypto.randomUUID());
}

async function createPortal({ secret, customerId, frontendUrl }) {
  if (!customerId) throw new Error("No billing customer is linked to this account");
  return stripeRequest("billing_portal/sessions", secret, {
    customer: customerId,
    return_url: frontendUrl + "/?billing=portal"
  });
}

module.exports = { verifyStripeSignature, stripeRequest, createCheckout, createPortal };
