import { describe, expect, it } from "vitest";
import { verifySlackEventRequest } from "./event-verification.ts";

const secret = "fixture-signing-secret";
const timestamp = "1700000000";
const now = Number(timestamp) * 1000;

async function signatureFor(body: string, at = timestamp, signingSecret = secret): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(signingSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(`v0:${at}:${body}`));
  return `v0=${[...new Uint8Array(signature)].map((value) => value.toString(16).padStart(2, "0")).join("")}`;
}

async function verify(body: string, overrides: Partial<Parameters<typeof verifySlackEventRequest>[0]> = {}) {
  return verifySlackEventRequest({
    timestamp,
    signature: await signatureFor(body),
    rawBody: body,
    configuredAppId: "A0C8QRPSZ7Z",
    signingSecret: secret,
    now,
    ...overrides,
  });
}

describe("Slack inbound event verification", () => {
  it("accepts a signed event for the configured app", async () => {
    const body = JSON.stringify({ type: "event_callback", api_app_id: "A0C8QRPSZ7Z" });

    await expect(verify(body)).resolves.toEqual({
      valid: true,
      appId: "A0C8QRPSZ7Z",
      challenge: null,
    });
  });

  it("rejects a signed event for another app", async () => {
    const body = JSON.stringify({ type: "event_callback", api_app_id: "AOTHER" });

    await expect(verify(body)).resolves.toEqual({ valid: false, reason: "app" });
  });

  it("rejects stale timestamps and invalid signatures", async () => {
    const body = JSON.stringify({ type: "event_callback", api_app_id: "A0C8QRPSZ7Z" });

    await expect(verify(body, { now: now + 5 * 60_000 + 1 })).resolves.toEqual({
      valid: false,
      reason: "timestamp",
    });
    await expect(verify(body, { signature: `v0=${"0".repeat(64)}` })).resolves.toEqual({
      valid: false,
      reason: "signature",
    });
  });

  it("accepts a signed url_verification challenge without app_id", async () => {
    const body = JSON.stringify({ type: "url_verification", challenge: "challenge-value" });

    await expect(verify(body)).resolves.toEqual({
      valid: true,
      appId: "A0C8QRPSZ7Z",
      challenge: "challenge-value",
    });
  });

  it("rejects oversized bodies", async () => {
    await expect(verify("x".repeat(64 * 1024 + 1))).resolves.toEqual({
      valid: false,
      reason: "body_too_large",
    });
  });
});
