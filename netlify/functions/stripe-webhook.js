const crypto = require('crypto');

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const SUPABASE_URL = 'https://ydxriywpkkdptwcuqaaj.supabase.co/rest/v1';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// This Stripe account is shared across multiple apps in the suite.
// Only Price IDs listed here belong to SongVault -- anything else is ignored.
const PRICE_MAP = {
  'price_1UDOORRru8MEHEIAGMTIfYg1': { tier: 'standard', usage_limit: null }
};

function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader) return false;
  const parts = Object.fromEntries(sigHeader.split(',').map(p => p.split('=')));
  const timestamp = parts.t;
  const signature = parts.v1;
  if (!timestamp || !signature) return false;
  const signedPayload = `${timestamp}.${rawBody}`;
  const expected = crypto.createHmac('sha256', secret).update(signedPayload, 'utf8').digest('hex');
  try {
    const sigBuf = Buffer.from(signature, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return false;
    return crypto.timingSafeEqual(sigBuf, expBuf);
  } catch (e) {
    return false;
  }
}

async function stripeGet(path) {
  const res = await fetch(`https://api.stripe.com/v1/${path}`, {
    headers: { 'Authorization': `Bearer ${STRIPE_SECRET_KEY}` }
  });
  if (!res.ok) throw new Error(`Stripe GET ${path} failed: ${res.status} ${await res.text()}`);
  return res.json();
}

async function supabaseUpsertSubscription(userId, fields) {
  const headers = {
    'apikey': SUPABASE_SERVICE_ROLE_KEY,
    'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json',
    'Accept-Profile': 'song_vault',
    'Content-Profile': 'song_vault'
  };
  const patchRes = await fetch(`${SUPABASE_URL}/subscriptions?user_id=eq.${userId}`, {
    method: 'PATCH',
    headers: { ...headers, 'Prefer': 'return=representation' },
    body: JSON.stringify(fields)
  });
  const patched = await patchRes.json();
  if (Array.isArray(patched) && patched.length > 0) return patched[0];
  // No existing row (shouldn't normally happen since the app bootstraps one on login,
  // but this makes the webhook self-sufficient as a fallback per the blueprint).
  const insertRes = await fetch(`${SUPABASE_URL}/subscriptions`, {
    method: 'POST',
    headers: { ...headers, 'Prefer': 'return=representation' },
    body: JSON.stringify({ user_id: userId, ...fields })
  });
  const inserted = await insertRes.json();
  return Array.isArray(inserted) ? inserted[0] : inserted;
}

async function supabaseFindBySubscriptionId(stripeSubscriptionId) {
  const res = await fetch(`${SUPABASE_URL}/subscriptions?stripe_subscription_id=eq.${stripeSubscriptionId}&limit=1`, {
    headers: {
      'apikey': SUPABASE_SERVICE_ROLE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      'Accept-Profile': 'song_vault'
    }
  });
  const rows = await res.json();
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const rawBody = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('utf8') : event.body;
  const sigHeader = event.headers['stripe-signature'] || event.headers['Stripe-Signature'];

  if (!verifyStripeSignature(rawBody, sigHeader, STRIPE_WEBHOOK_SECRET)) {
    return { statusCode: 400, body: 'Invalid signature' };
  }

  let stripeEvent;
  try {
    stripeEvent = JSON.parse(rawBody);
  } catch (e) {
    return { statusCode: 400, body: 'Invalid JSON' };
  }

  try {
    if (stripeEvent.type === 'checkout.session.completed') {
      const session = stripeEvent.data.object;
      const userId = session.client_reference_id;
      const subscriptionId = session.subscription;
      if (!userId || !subscriptionId) {
        return { statusCode: 200, body: 'No client_reference_id or subscription on session; ignoring' };
      }

      const subscription = await stripeGet(`subscriptions/${subscriptionId}?expand[]=items.data.price`);
      const priceId = subscription?.items?.data?.[0]?.price?.id;
      const match = PRICE_MAP[priceId];

      if (!match) {
        // Belongs to a different app on the same shared Stripe account -- not ours to handle.
        return { statusCode: 200, body: 'Price ID not recognized by this app; ignoring' };
      }

      await supabaseUpsertSubscription(userId, {
        status: 'active',
        tier: match.tier,
        usage_limit: match.usage_limit,
        stripe_customer_id: session.customer || null,
        stripe_subscription_id: subscriptionId,
        updated_at: new Date().toISOString()
      });

      return { statusCode: 200, body: 'Subscription activated' };
    }

    if (stripeEvent.type === 'customer.subscription.deleted') {
      const subscription = stripeEvent.data.object;
      const row = await supabaseFindBySubscriptionId(subscription.id);
      if (!row) {
        return { statusCode: 200, body: 'No matching subscription row; ignoring' };
      }
      await supabaseUpsertSubscription(row.user_id, {
        status: 'inactive',
        updated_at: new Date().toISOString()
      });
      return { statusCode: 200, body: 'Subscription deactivated' };
    }

    return { statusCode: 200, body: `Ignored event type: ${stripeEvent.type}` };
  } catch (err) {
    console.error('Webhook handler error:', err.message);
    return { statusCode: 500, body: 'Internal error' };
  }
};
