// The browser's own WebAuthn API and nothing else (Story 1.22): the server's JSON options become
// the PublicKeyCredentialCreationOptions navigator.credentials.create takes, and the credential it
// returns becomes the JSON the server verifies. Binary values cross as base64url with no padding.

import type { CredentialCreationOptionsResponse, CredentialRegistrationRequest } from '@gatekeep/api-client';

export function fromBase64Url(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function toBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The server's creation options, as navigator.credentials.create takes them. */
export function creationOptions(options: CredentialCreationOptionsResponse): PublicKeyCredentialCreationOptions {
  return {
    rp: { id: options.rp.id, name: options.rp.name },
    user: { id: fromBase64Url(options.user.id), name: options.user.name, displayName: options.user.displayName },
    challenge: fromBase64Url(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams.map((p) => ({ type: 'public-key', alg: Number(p.alg) })),
    timeout: Number(options.timeout),
    attestation: options.attestation as AttestationConveyancePreference,
    authenticatorSelection: {
      residentKey: options.authenticatorSelection.residentKey as ResidentKeyRequirement,
      userVerification: options.authenticatorSelection.userVerification as UserVerificationRequirement,
    },
    excludeCredentials: options.excludeCredentials.map((c) => ({
      type: 'public-key',
      id: fromBase64Url(c.id),
      ...(c.transports && c.transports.length > 0 ? { transports: c.transports as AuthenticatorTransport[] } : {}),
    })),
  };
}

/** The credential create returned, as the server's complete call takes it. */
export function registrationRequest(credential: PublicKeyCredential): CredentialRegistrationRequest {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: toBase64Url(response.attestationObject),
      transports: typeof response.getTransports === 'function' ? response.getTransports() : [],
    },
  };
}

/** A ceremony the user or the browser ended without a credential: the page stays as it is. */
export function isCancelled(error: unknown): boolean {
  return error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError');
}

/** The authenticator already holds a credential the options excluded: this device is already registered. */
export function isAlreadyRegistered(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'InvalidStateError';
}
