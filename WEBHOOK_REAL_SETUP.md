# Real Webhook Integration

This project sends real outbound HTTPS webhook requests when scholarship application events occur. It is not limited to a demo receiver.

## Events

- `APPLICATION_SUBMITTED`
- `DOCUMENT_UPLOADED`
- `APPLICATION_VERIFIED`
- `APPLICATION_REJECTED`
- `APPLICATION_STATUS_CHANGED`

## Configuration

Add these to the project-root `.env` (never commit this file):

```env
WEBHOOK_RECEIVER_URL=https://your-domain.example/webhooks/scholarship
WEBHOOK_SECRET=your-long-random-secret
WEBHOOK_TIMEOUT_MS=10000
WEBHOOK_MAX_ATTEMPTS=5
WEBHOOK_RETRY_DELAY_MS=30000
```

`WEBHOOK_RECEIVER_URL` must be an HTTPS endpoint owned by your application or a trusted integration provider. `WEBHOOK_SECRET` is strongly recommended.

## Request

Each event is sent as JSON:

```json
{
  "id": "evt_<uuid>",
  "event": "APPLICATION_SUBMITTED",
  "timestamp": "2026-09-30T00:00:00.000Z",
  "applicationId": "123",
  "data": {
    "publicId": "APP-...",
    "newStatus": "INSTITUTION_VERIFICATION"
  }
}
```

Headers include `X-ScholarPath-Event`, `X-ScholarPath-Event-Id`, and `Idempotency-Key`. When `WEBHOOK_SECRET` is configured, `x-webhook-signature` contains `v1=<HMAC-SHA256>` over the exact request body.

## Reliability

Webhook events are stored in `webhook_events` before delivery. Failed/timeout deliveries are retried by the backend worker up to `WEBHOOK_MAX_ATTEMPTS`. Because delivery is asynchronous, a receiver outage does not roll back a successfully committed scholarship application. Receivers should treat `Idempotency-Key` / event `id` as the deduplication key.

## Receiver requirements

Return any 2xx response after validating the signature and recording the event. Do not perform long-running work before responding.
