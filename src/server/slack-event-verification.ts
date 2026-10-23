import { verifySourceHmac } from "../triggers/sources/signature.ts";

/** Maximum clock skew accepted for a Slack request timestamp. */
const maximumClockSkewMs = 5 * 60_000;

/** Maximum request body size, consistent with existing event sources. */
export const slackEventMaximumBodyBytes: number = 64 * 1024;

export interface SlackEventVerificationInput {
  /** Value of the X-Slack-Request-Timestamp header. */
  timestamp: string;
  /** Value of the X-Slack-Signature header. */
  signature: string;
  /** Raw request body bytes; they must not be re-serialized. */
  rawBody: Uint8Array;
  /** App ID of the Slack application configured in this runtime. */
  configuredAppId: string;
  /** Signing secret of the Slack application configured in this runtime. */
  signingSecret: string;
  /** Current time in milliseconds; injectable for tests. */
  now?: number;
}

export type SlackEventVerificationResult =
  | { valid: true; appId: string; challenge: string | null }
  | {
      valid: false;
      reason: "signature" | "timestamp" | "payload" | "app" | "body_too_large";
    };

/**
 * Reads a request body without buffering more than the Slack event limit.
 *
 * Returns undefined when the request exceeds the limit. The actual stream size is
 * enforced even when Content-Length is absent or understated.
 */
export async function readSlackEventRequestBody(request: Request): Promise<Uint8Array | undefined> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > slackEventMaximumBodyBytes) {
    return undefined;
  }
  if (!request.body) return new Uint8Array();

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      totalBytes += value.byteLength;
      if (totalBytes > slackEventMaximumBodyBytes) {
        await reader.cancel().catch(() => undefined);
        return undefined;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

/**
 * Verifies the signature, timestamp window, and App ID of an inbound Slack request.
 *
 * Verification only: this function does not persist, deduplicate, or schedule events.
 */
export async function verifySlackEventRequest(
  input: SlackEventVerificationInput,
): Promise<SlackEventVerificationResult> {
  const now = input.now ?? Date.now();
  if (input.rawBody.byteLength > slackEventMaximumBodyBytes) {
    return { valid: false, reason: "body_too_large" };
  }
  if (!/^\d{10}$/.test(input.timestamp) || Math.abs(now - Number(input.timestamp) * 1000) > maximumClockSkewMs) {
    return { valid: false, reason: "timestamp" };
  }
  if (!/^v0=[0-9a-f]{64}$/.test(input.signature)) {
    return { valid: false, reason: "signature" };
  }
  if (!input.signingSecret) {
    return { valid: false, reason: "signature" };
  }

  const prefix = new TextEncoder().encode(`v0:${input.timestamp}:`);
  const signed = new Uint8Array(prefix.length + input.rawBody.byteLength);
  signed.set(prefix);
  signed.set(input.rawBody, prefix.length);
  const valid = await verifySourceHmac(signed, input.signature.slice(3), input.signingSecret);
  if (!valid) {
    return { valid: false, reason: "signature" };
  }

  // Only parse the body after its signature is trusted.
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input.rawBody));
  } catch {
    return { valid: false, reason: "payload" };
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return { valid: false, reason: "payload" };
  }
  const record = payload as Record<string, unknown>;
  const isChallenge = record.type === "url_verification";
  if (!isChallenge && record.api_app_id !== input.configuredAppId) {
    return { valid: false, reason: "app" };
  }
  return {
    valid: true,
    appId: isChallenge ? input.configuredAppId : String(record.api_app_id),
    challenge: isChallenge && typeof record.challenge === "string" ? record.challenge : null,
  };
}
