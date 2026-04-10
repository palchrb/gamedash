/**
 * WebAuthn ceremonies for the kids portal (discoverable credentials).
 *
 * Unlike knock-passkey.ts (which requires a token to look up the user first
 * and sends `allowCredentials`), the portal uses discoverable credentials
 * just like admin-passkey.ts — the browser picks which passkey to present
 * and we identify the kid by their credential ID via `findUserByCredentialId`.
 *
 * Only authentication is supported here; registration still goes through
 * the token-based `/u/:token/webauthn/register/*` flow.
 */

import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import type { AuthenticatorTransportFuture } from "@simplewebauthn/types";
import { config } from "../config";
import { logger } from "../logger";
import { findUserByCredentialId, updateCredentialCounter } from "../repos/users";
import { putChallenge, takeChallenge } from "./challenges";

function rpID(): string {
  return config().ADMIN_RP_ID;
}

function expectedOrigin(): string {
  return config().ADMIN_ORIGIN;
}

function b64urlToBytes(b64url: string): Uint8Array {
  const pad = b64url.length % 4 === 0 ? "" : "=".repeat(4 - (b64url.length % 4));
  const b64 = (b64url + pad).replace(/-/gu, "+").replace(/_/gu, "/");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

const PORTAL_CHALLENGE_KEY = "portal:current";

export async function generatePortalAuthenticationOpts(): Promise<unknown> {
  const options = await generateAuthenticationOptions({
    rpID: rpID(),
    userVerification: "preferred",
  });
  putChallenge(PORTAL_CHALLENGE_KEY, options.challenge);
  return options;
}

export async function verifyPortalAuthentication(params: {
  response: unknown;
}): Promise<{ userId: string; credentialId: string; newCounter: number }> {
  const expectedChallenge = takeChallenge(PORTAL_CHALLENGE_KEY);
  if (!expectedChallenge) {
    throw new Error("no pending authentication challenge");
  }

  const responseObj = params.response as { id?: string };
  const credentialId = responseObj.id;
  if (!credentialId || typeof credentialId !== "string") {
    throw new Error("missing credential id in response");
  }

  const lookup = await findUserByCredentialId(credentialId);
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
    logger().warn(
      { err: (err as Error).message },
      "portal authentication verification failed",
    );
    throw new Error("authentication verification failed");
  }

  if (!verification.verified) throw new Error("authentication not verified");

  const newCounter = verification.authenticationInfo.newCounter;
  if (newCounter < lookup.credential.counter) {
    logger().error(
      {
        userId: lookup.user.id,
        credentialId,
        storedCounter: lookup.credential.counter,
        newCounter,
      },
      "portal authenticator counter rolled back — possible clone",
    );
    throw new Error("counter rollback detected");
  }

  await updateCredentialCounter(lookup.user.id, credentialId, newCounter);
  return { userId: lookup.user.id, credentialId, newCounter };
}
