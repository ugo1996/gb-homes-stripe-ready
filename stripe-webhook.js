const crypto = require('crypto');

module.exports.config = { api: { bodyParser: false } };

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(Buffer.from(c)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function validSignature(body, header, secret) {
  if (!header || !secret) return false;
  const parts = header.split(',');
  const t = parts.find(p => p.startsWith('t='));
  const sigs = parts.filter(p => p.startsWith('v1=')).map(p => p.slice(3));
  if (!t || !sigs.length) return false;
  const expected = crypto.createHmac('sha256', secret)
    .update(`${t.slice(2)}.${body.toString('utf8')}`, 'utf8').digest('hex');
  return sigs.some(sig => {
    try {
      return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
    } catch { return false; }
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!process.env.STRIPE_WEBHOOK_SECRET)
    return res.status(500).json({ error: 'Webhook secret is not configured.' });

  try {
    const body = await readRawBody(req);
    if (!validSignature(body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET))
      return res.status(400).json({ error: 'Invalid Stripe signature.' });

    const event = JSON.parse(body.toString('utf8'));
    if (event.type === 'checkout.session.completed') {
      const s = event.data && event.data.object;
      console.log('GB Homes paid booking received', {
        session_id: s && s.id,
        payment_status: s && s.payment_status,
        customer_email: s && s.customer_details && s.customer_details.email,
        metadata: s && s.metadata
      });
    }
    return res.status(200).json({ received: true });
  } catch (e) {
    console.error('Stripe webhook error', e);
    return res.status(400).json({ error: 'Webhook could not be processed.' });
  }
};
