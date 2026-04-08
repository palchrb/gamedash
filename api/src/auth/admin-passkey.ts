/**
 * WebAuthn ceremonies for admin passkey auth.
 *
 * This file is a thin, opinionated wrapper around @simplewebauthn/server
 * that hides the details of the two ceremonies from the route layer.
 *
 * Registration:
 *   1. generateRegistrationOpts(adminId) → returns options JSON for
 *      navigator.credentials.create(). Stores the challenge keyed by
 *      `reg:<adminId>` in the in-memory challenge store (2-min TTL).
 *   2. verifyRegistration(adminId, response) → verifies the browser's
 *      attestation, checks the stored challenge, persists the credential,
 *      and wipes the challenge.
 *
 * Authentication:
 *   1. generateAuthenticationOpts() → fresh challenge, stored under
 *      `auth:<id>`. Returns options to navigator.credentials.get().
 *   2. verifyAuthentication(response) → looks up the credential by id,
 *      verifies the signature, and if everything is good returns the
 *      adminId + updated counter.
 *
 * Counters: every successful authentication persists the new counter so
 * we can detect cloned authenticators (newCounter <= stored counter is
 * rejected as replay). Passkeys synced across Apple/Google devices may
 * legitimately report counter = 0 forever — we allow that by only
 * rejecting strict *decreases*, not equality.
 */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import type { AuthenticatorTransportFuture } from "@simplewebauthn/types";
import { config } from "../config";
import { logger } from "../logger";
import {
  addAdminCredential,
  findAdminById,
  findAdminByCredentialId,
  updateAdminCredentialCounter,
} from "../repos/admin";
import type { AdminRecord, WebAuthnCredential } from "../schemas";
import { putChallenge, takeChallenge } from "./challenges";

// ── helpers ────────────────────────────────────────────────────────────

function rpID(): string {
  return config().ADMIN_RP_ID;
}

function rpName(): string {
  return config().ADMIN_RP_NAME;
}

function expectedOrigin(): string {
  return config().ADMIN_ORIGIN;
}

function b64urlToBytes(b64url: string): Uint8Array {
  const pad = b64url.length % 4 === 0 ? "" : "=".repeat(4 - (b64url.length % 4));
  const b64 = (b64url + pad).replace(/-/gu, "+").replace(/_/gu, "/");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function bytesToB64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function stringToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "utf8"));
}

// ── registration ───────────────────────────────────────────────────────

export async function generateRegistrationOpts(admin: AdminRecord): Promise<unknown> {
  const options = await generateRegistrationOptions({
    rpName: rpName(),
    rpID: rpID(),
    userName: admin.name,
    userID: stringToBytes(admin.id),
    userDisplayName: admin.name,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    excludeCredentials: admin.credentials.map((c) => ({
      id: c.id,
      transports: (c.transports ?? []) as AuthenticatorTransportFuture[],
    })),
  });
  putChallenge(`reg:${admin.id}`, options.challenge);
  return options;
}

export async function verifyRegistration(params: {
  adminId: string;
  response: unknown;
  deviceLabel?: string;
}): Promise<{ credential: WebAuthnCredential }> {
  const expectedChallenge = takeChallenge(`reg:${params.adminId}`);
  if (!expectedChallenge) {
    throw new Error("no pending registration challenge");
  }
  const admin = await findAdminById(params.adminId);
  if (!admin) throw new Error("admin not found");

  let verification: VerifiedRegistrationResponse;
  try {
    verification = await verifyRegistrationResponse({
      response: params.response as Parameters<typeof verifyRegistrationResponse>[0]["response"],
      expectedChallenge,
      expectedOrigin: expectedOrigin(),
      expectedRPID: rpID(),
      requireUserVerification: true,
    });
  } catch (err) {
    logger().warn({ err: (err as Error).message }, "admin registration verification failed");
    throw new Error("registration verification failed");
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error("registration not verified");
  }

  const info = verification.registrationInfo;
  const credential: WebAuthnCredential = {
    id: info.credential.id,
    publicKey: bytesToB64url(info.credential.publicKey),
    counter: info.credential.counter,
    transports: info.credential.transports,
    deviceLabel: params.deviceLabel,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
  };
  await addAdminCredential(params.adminId, credential);
  return { credential };
}

// ── authentication ─────────────────────────────────────────────────────

export async function generateAuthenticationOpts(challengeKey: string): Promise<unknown> {
  const options = await generateAuthenticationOptions({
    rpID: rpID(),
    userVerification: "preferred",
  });
  putChallenge(challengeKey, options.challenge);
  return options;
}

export async function verifyAuthentication(params: {
  challengeKey: string;
  response: unknown;
}): Promise<{ adminId: string; credentialId: string; newCounter: number }> {
  const expectedChallenge = takeChallenge(params.challengeKey);
  if (!expectedChallenge) {
    throw new Error("no pending authentication challenge");
  }

  const responseObj = params.response as { id?: string };
  const credentialId = responseObj.id;
  if (!credentialId || typeof credentialId !== "string") {
    throw new Error("missing credential id in response");
  }

  const lookup = await findAdminByCredentialId(credentialId);
  if (!lookup) throw new Error("unknown credential");

  let verification: VerifiedAuthenticationResponse;
  try {
    verification = await verifyAuthenticationResponse({
      response: params.response as Parameters<
        typeof verifyAuthenticationResponse
      >[0]["response"],
      expectedChallenge,
      expectedOrigin: expectedOrigin(),
      expectedRPID: rpID(),
      credential: {
        id: lookup.credential.id,
        publicKey: b64urlToBytes(lookup.credential.publicKey),
        counter: lookup.credential.counter,
        transports: lookup.credential.transports as AuthenticatorTransportFuture[] | undefined,
      },
      requireUserVerification: true,
    });
  } catch (err) {
    logger().warn({ err: (err as Error).message }, "admin authentication verification failed");
    throw new Error("authentication verification failed");
  }

  if (!verification.verified) throw new Error("authentication not verified");

  const newCounter = verification.authenticationInfo.newCounter;
  // Allow equal counters (stateless passkeys) but reject strict rollback.
  if (newCounter < lookup.credential.counter) {
    logger().error(
      {
        adminId: lookup.admin.id,
        credentialId,
        storedCounter: lookup.credential.counter,
        newCounter,
      },
      "authenticator counter rolled back — possible clone",
    );
    throw new Error("counter rollback detected");
  }

  await updateAdminCredentialCounter(lookup.admin.id, credentialId, newCounter);
  return { adminId: lookup.admin.id, credentialId, newCounter };
}
