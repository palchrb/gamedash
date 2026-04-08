/**
 * WebAuthn ceremonies for knock PWA users (Phase 3).
 *
 * Parallels admin-passkey.ts but acts on UserRecord + KnockCredential
 * instead of AdminRecord + AdminCredential. The split lets each set of
 * credentials live in its own file and use its own challenge store
 * namespace (`kreg:<userId>` / `kauth:<userId>`).
 *
 * Registration of new devices is gated by `user.registrationOpenUntil`:
 * an admin opens a short window (default 24 h, configurable via
 * KNOCK_REGISTRATION_TTL_HOURS) when creating the user or when adding
 * a new device. After the first successful registration the window is
 * closed automatically by `addKnockCredential` in the users repo.
 */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type VerifiedAuthenticationResponse,
  type VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import type { AuthenticatorTransportFuture } from "@simplewebauthn/types";
import { config } from "../config";
import { logger } from "../logger";
import {
  addKnockCredential,
  findById,
  updateCredentialCounter,
} from "../repos/users";
import type { KnockCredential, UserRecord } from "../schemas";
import { putChallenge, takeChallenge } from "./challenges";

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

function regChallengeKey(userId: string): string {
  return `kreg:${userId}`;
}

function authChallengeKey(userId: string): string {
  return `kauth:${userId}`;
}

// ── registration ───────────────────────────────────────────────────────

export function isRegistrationOpen(user: UserRecord): boolean {
  if (!user.registrationOpenUntil) return false;
  return Date.now() < new Date(user.registrationOpenUntil).getTime();
}

export async function generateKnockRegistrationOpts(
  user: UserRecord,
): Promise<unknown> {
  const options = await generateRegistrationOptions({
    rpName: rpName(),
    rpID: rpID(),
    userName: user.name,
    userID: stringToBytes(user.id),
    userDisplayName: user.name,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    excludeCredentials: user.credentials.map((c) => ({
      id: c.id,
      transports: (c.transports ?? []) as AuthenticatorTransportFuture[],
    })),
  });
  putChallenge(regChallengeKey(user.id), options.challenge);
  return options;
}

export async function verifyKnockRegistration(params: {
  userId: string;
  response: unknown;
  deviceLabel?: string;
}): Promise<{ credential: KnockCredential }> {
  const expectedChallenge = takeChallenge(regChallengeKey(params.userId));
  if (!expectedChallenge) {
    throw new Error("no pending registration challenge");
  }
  const user = await findById(params.userId);
  if (!user) throw new Error("user not found");

  let verification: VerifiedRegistrationResponse;
  try {
    verification = await verifyRegistrationResponse({
      response: params.response as Parameters<
        typeof verifyRegistrationResponse
      >[0]["response"],
      expectedChallenge,
      expectedOrigin: expectedOrigin(),
      expectedRPID: rpID(),
      requireUserVerification: true,
    });
  } catch (err) {
    logger().warn(
      { err: (err as Error).message, userId: params.userId },
      "knock registration verification failed",
    );
    throw new Error("registration verification failed");
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error("registration not verified");
  }

  const info = verification.registrationInfo;
  const credential: KnockCredential = {
    id: info.credential.id,
    publicKey: bytesToB64url(info.credential.publicKey),
    counter: info.credential.counter,
    transports: info.credential.transports,
    ...(params.deviceLabel !== undefined ? { deviceLabel: params.deviceLabel } : {}),
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
  };
  await addKnockCredential(params.userId, credential);
  return { credential };
}

// ── authentication ─────────────────────────────────────────────────────

export async function generateKnockAuthenticationOpts(
  user: UserRecord,
): Promise<unknown> {
  const options = await generateAuthenticationOptions({
    rpID: rpID(),
    userVerification: "preferred",
    allowCredentials: user.credentials.map((c) => ({
      id: c.id,
      transports: (c.transports ?? []) as AuthenticatorTransportFuture[],
    })),
  });
  putChallenge(authChallengeKey(user.id), options.challenge);
  return options;
}

export async function verifyKnockAuthentication(params: {
  user: UserRecord;
  response: unknown;
}): Promise<{ credentialId: string; newCounter: number }> {
  const expectedChallenge = takeChallenge(authChallengeKey(params.user.id));
  if (!expectedChallenge) {
    throw new Error("no pending authentication challenge");
  }

  const responseObj = params.response as { id?: string };
  const credentialId = responseObj.id;
  if (!credentialId || typeof credentialId !== "string") {
    throw new Error("missing credential id in response");
  }

  const stored = params.user.credentials.find((c) => c.id === credentialId);
  if (!stored) throw new Error("unknown credential");

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
        id: stored.id,
        publicKey: b64urlToBytes(stored.publicKey),
        counter: stored.counter,
        transports: stored.transports as AuthenticatorTransportFuture[] | undefined,
      },
      requireUserVerification: true,
    });
  } catch (err) {
    logger().warn(
      { err: (err as Error).message, userId: params.user.id },
      "knock authentication verification failed",
    );
    throw new Error("authentication verification failed");
  }

  if (!verification.verified) throw new Error("authentication not verified");

  const newCounter = verification.authenticationInfo.newCounter;
  if (newCounter < stored.counter) {
    logger().error(
      {
        userId: params.user.id,
        credentialId,
        storedCounter: stored.counter,
        newCounter,
      },
      "knock authenticator counter rolled back — possible clone",
    );
    throw new Error("counter rollback detected");
  }

  await updateCredentialCounter(params.user.id, credentialId, newCounter);
  return { credentialId, newCounter };
}
