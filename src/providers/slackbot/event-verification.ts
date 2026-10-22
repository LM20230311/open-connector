import { verifySourceHmac } from "../../triggers/sources/signature.ts";

/** Maximum clock skew accepted for a Slack request timestamp. */
const maximumClockSkewMs = 5 * 60_000;

/** Maximum request body size, consistent with existing event sources. */
export const slackEventMaximumBodyBytes: number = 64 * 1024;

export interface SlackEventVerificationInput {
  /** Value of the X-Slack-Request-Timestamp header. */
  timestamp: string;
  /** Value of the X-Slack-Signature header. */
  signature: string;
  /** Raw request body; it must not be re-serialized. */
  rawBody: string;
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
 * Verifies the signature, timestamp window, and App ID of an inbound Slack request.
 *
 * Verification only: this function does not persist, deduplicate, or schedule events.
 */
export async function verifySlackEventRequest(
  input: SlackEventVerificationInput,
): Promise<SlackEventVerificationResult> {
  const now = input.now ?? Date.now();
  if (new TextEncoder().encode(input.rawBody).byteLength > slackEventMaximumBodyBytes) {
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
  const body = new TextEncoder().encode(input.rawBody);
  const signed = new Uint8Array(prefix.length + body.length);
  signed.set(prefix);
  signed.set(body, prefix.length);
  const valid = await verifySourceHmac(signed, input.signature.slice(3), input.signingSecret);
  if (!valid) {
    return { valid: false, reason: "signature" };
  }

  // Only parse the body after its signature is trusted.
  let payload: unknown;
  try {
    payload = JSON.parse(input.rawBody);
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
