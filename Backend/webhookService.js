'use strict';

const crypto = require('crypto');
const { randomUUID } = require('crypto');

const WEBHOOK_TIMEOUT_MS = Number(process.env.WEBHOOK_TIMEOUT_MS || 10000);
const MAX_ATTEMPTS = Math.max(1, Number(process.env.WEBHOOK_MAX_ATTEMPTS || 5));
const RETRY_DELAY_MS = Math.max(1000, Number(process.env.WEBHOOK_RETRY_DELAY_MS || 30000));
const ALLOWED_EVENTS = new Set([
  'APPLICATION_SUBMITTED',
  'APPLICATION_STATUS_CHANGED',
  'APPLICATION_VERIFIED',
  'APPLICATION_REJECTED',
  'DOCUMENT_UPLOADED'
]);

const inFlight = new Set();
let retryTimer = null;

function receiverUrl() {
  return String(process.env.WEBHOOK_RECEIVER_URL || '').trim();
}

function verifyWebhookSignature(rawBody, signatureHeader) {
  const secret = String(process.env.WEBHOOK_SECRET || '');
  if (!secret) return { valid: false, reason: 'WEBHOOK_SECRET not configured' };
  if (!signatureHeader) return { valid: false, reason: 'Missing x-webhook-signature header' };
  try {
    const [scheme, hex] = String(signatureHeader).split('=');
    if (scheme !== 'v1' || !hex || !/^[0-9a-f]+$/i.test(hex)) {
      return { valid: false, reason: 'Invalid signature format' };
    }
    const expected = crypto.createHmac('sha256', secret).update(String(rawBody || ''), 'utf8').digest('hex');
    const left = Buffer.from(hex, 'hex');
    const right = Buffer.from(expected, 'hex');
    if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) {
      return { valid: false, reason: 'Signature mismatch' };
    }
    return { valid: true };
  } catch (_) {
    return { valid: false, reason: 'Signature verification error' };
  }
}

function signPayload(body) {
  const secret = String(process.env.WEBHOOK_SECRET || '');
  if (!secret) return null;
  const hex = crypto.createHmac('sha256', secret).update(body, 'utf8').digest('hex');
  return `v1=${hex}`;
}

function makePayload(eventType, applicationId, data, eventId = null) {
  const safeData = data && typeof data === 'object' ? { ...data } : {};
  delete safeData.password;
  delete safeData.password_hash;
  delete safeData.token;
  delete safeData.documentContent;
  delete safeData.fileBuffer;
  return {
    id: eventId || undefined,
    event: eventType,
    timestamp: new Date().toISOString(),
    applicationId: String(applicationId),
    data: safeData
  };
}

async function storeEvent(pool, eventId, eventType, payload) {
  const [r] = await pool.query(
    'INSERT INTO webhook_events (event_id, event_type, status, payload) VALUES (?, ?, ?, ?)',
    [eventId, eventType, 'pending', JSON.stringify(payload)]
  );
  return r.insertId;
}

async function recordDelivery(pool, eventId, status, errorMessage) {
  const safeMsg = errorMessage
    ? String(errorMessage).replace(/password|secret|token|Authorization/gi, '[REDACTED]').slice(0, 500)
    : null;
  await pool.query(
    'UPDATE webhook_events SET status=?, retries=retries+1, updated_at=NOW() WHERE event_id=?',
    [status, eventId]
  );
  if (safeMsg) {
    await pool.query(
      'UPDATE webhook_events SET payload=JSON_SET(payload, "$.deliveryError", ?) WHERE event_id=?',
      [safeMsg, eventId]
    );
  }
}

async function deliverWebhook(pool, eventId, payload) {
  const url = receiverUrl();
  if (!url) {
    await pool.query('UPDATE webhook_events SET status=?, updated_at=NOW() WHERE event_id=?', ['queued', eventId]);
    return { status: 'queued', reason: 'WEBHOOK_RECEIVER_URL not configured' };
  }

  if (inFlight.has(eventId)) return { status: 'in_flight' };
  inFlight.add(eventId);

  const body = JSON.stringify({ ...payload, id: eventId });
  const signature = signPayload(body);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);

  try {
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'ScholarPath-Webhook/1.0',
      'X-ScholarPath-Event': payload.event,
      'X-ScholarPath-Event-Id': eventId,
      'Idempotency-Key': eventId
    };
    if (signature) headers['x-webhook-signature'] = signature;

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body,
      signal: controller.signal
    });

    if (!response.ok) throw new Error(`Receiver responded with HTTP ${response.status}`);

    await pool.query(
      'UPDATE webhook_events SET status=?, updated_at=NOW() WHERE event_id=?',
      ['delivered', eventId]
    );
    return { status: 'delivered', httpStatus: response.status };
  } catch (err) {
    const status = err.name === 'AbortError' ? 'timeout' : 'failed';
    await recordDelivery(pool, eventId, status, err.message);
    throw err;
  } finally {
    clearTimeout(timeout);
    inFlight.delete(eventId);
  }
}

async function emitApplicationEvent(pool, eventType, applicationId, data = {}) {
  try {
    if (!ALLOWED_EVENTS.has(eventType) || applicationId == null) return null;
    const eventId = `evt_${randomUUID()}`;
    const payload = makePayload(eventType, applicationId, data, eventId);
    await storeEvent(pool, eventId, eventType, payload);

    // Delivery is asynchronous so a webhook outage never rolls back the
    // application transaction that has already committed.
    setImmediate(() => deliverWebhook(pool, eventId, payload).catch((err) => {
      console.error('Webhook delivery error for', eventId, ':', err.message);
    }));
    return eventId;
  } catch (err) {
    console.error('Webhook emit failed:', err.message);
    return null;
  }
}

async function retryPendingWebhooks(pool) {
  if (!receiverUrl()) return;
  try {
    const [rows] = await pool.query(
      `SELECT event_id, event_type, payload, retries
       FROM webhook_events
       WHERE status IN ('pending','failed','timeout','queued') AND retries < ?
       ORDER BY created_at ASC LIMIT 20`,
      [MAX_ATTEMPTS]
    );

    for (const row of rows) {
      let payload = row.payload;
      if (typeof payload === 'string') {
        try { payload = JSON.parse(payload); } catch (_) { continue; }
      }
      await deliverWebhook(pool, row.event_id, payload).catch((err) => {
        console.error('Webhook retry failed for', row.event_id, ':', err.message);
      });
    }
  } catch (err) {
    console.error('Webhook retry worker error:', err.message);
  }
}

function startWebhookWorker(pool) {
  if (retryTimer) return;
  retryPendingWebhooks(pool);
  retryTimer = setInterval(() => retryPendingWebhooks(pool), RETRY_DELAY_MS);
  if (typeof retryTimer.unref === 'function') retryTimer.unref();
}

module.exports = {
  ALLOWED_EVENTS,
  verifyWebhookSignature,
  makePayload,
  signPayload,
  storeEvent,
  recordDelivery,
  deliverWebhook,
  emitApplicationEvent,
  startWebhookWorker
};
