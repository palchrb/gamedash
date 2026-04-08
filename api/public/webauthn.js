/*
 * Minimal browser-side WebAuthn helper.
 *
 * Converts between the base64url JSON shape emitted by the @simplewebauthn
 * server helpers and the ArrayBuffer fields that navigator.credentials
 * expects, without pulling in any npm dependency.
 *
 * Exposes two functions on `window`:
 *   webauthnRegister(options) → RegistrationResponseJSON
 *   webauthnAuthenticate(options) → AuthenticationResponseJSON
 * Each accepts the options object as returned from the server and returns
 * the JSON-friendly response ready to POST back to the verify endpoint.
 */

(function () {
  function b64urlToBytes(b64url) {
    const pad = b64url.length % 4 === 0 ? "" : "=".repeat(4 - (b64url.length % 4));
    const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeCreationOptions(opts) {
    const publicKey = Object.assign({}, opts, {
      challenge: b64urlToBytes(opts.challenge),
      user: Object.assign({}, opts.user, {
        id: b64urlToBytes(opts.user.id),
      }),
    });
    if (Array.isArray(opts.excludeCredentials)) {
      publicKey.excludeCredentials = opts.excludeCredentials.map((c) =>
        Object.assign({}, c, { id: b64urlToBytes(c.id) }),
      );
    }
    return publicKey;
  }

  function decodeRequestOptions(opts) {
    const publicKey = Object.assign({}, opts, {
      challenge: b64urlToBytes(opts.challenge),
    });
    if (Array.isArray(opts.allowCredentials)) {
      publicKey.allowCredentials = opts.allowCredentials.map((c) =>
        Object.assign({}, c, { id: b64urlToBytes(c.id) }),
      );
    }
    return publicKey;
  }

  function encodeRegistrationResponse(cred) {
    const response = cred.response;
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults
        ? cred.getClientExtensionResults()
        : {},
      response: {
        clientDataJSON: bytesToB64url(response.clientDataJSON),
        attestationObject: bytesToB64url(response.attestationObject),
        transports:
          typeof response.getTransports === "function" ? response.getTransports() : [],
      },
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
    };
  }

  function encodeAuthenticationResponse(cred) {
    const response = cred.response;
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults
        ? cred.getClientExtensionResults()
        : {},
      response: {
        clientDataJSON: bytesToB64url(response.clientDataJSON),
        authenticatorData: bytesToB64url(response.authenticatorData),
        signature: bytesToB64url(response.signature),
        userHandle: response.userHandle ? bytesToB64url(response.userHandle) : undefined,
      },
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
    };
  }

  window.webauthnRegister = async function (options) {
    if (!window.PublicKeyCredential) {
      throw new Error("WebAuthn is not supported in this browser");
    }
    const publicKey = decodeCreationOptions(options);
    const cred = await navigator.credentials.create({ publicKey });
    if (!cred) throw new Error("registration cancelled");
    return encodeRegistrationResponse(cred);
  };

  window.webauthnAuthenticate = async function (options) {
    if (!window.PublicKeyCredential) {
      throw new Error("WebAuthn is not supported in this browser");
    }
    const publicKey = decodeRequestOptions(options);
    const cred = await navigator.credentials.get({ publicKey });
    if (!cred) throw new Error("authentication cancelled");
    return encodeAuthenticationResponse(cred);
  };
})();
