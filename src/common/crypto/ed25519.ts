import { generateKeyPairSync, sign, verify, type KeyObject } from 'crypto';

/**
 * Ed25519 (EdDSA) primitives for the asymmetric ZT protocol. Ed25519 is
 * deterministic, needs no algorithm parameters, and is verified with the
 * public key alone — the private key stays in this service (the signer) and
 * never leaves it. Mirror of securechain-vault's ed25519.ts (the verifier).
 */

export function signEd25519(privateKey: KeyObject, canonical: string): string {
  // Ed25519 uses a null digest algorithm (the scheme hashes internally).
  return sign(null, Buffer.from(canonical, 'utf8'), privateKey).toString(
    'base64',
  );
}

export function verifyEd25519(
  publicKey: KeyObject,
  canonical: string,
  signatureB64: string,
): boolean {
  let signature: Buffer;
  try {
    signature = Buffer.from(signatureB64, 'base64');
  } catch {
    return false;
  }
  if (signature.length === 0) return false;

  try {
    return verify(null, Buffer.from(canonical, 'utf8'), publicKey, signature);
  } catch {
    return false;
  }
}

/** Test/rotation helper — generate a fresh Ed25519 key pair. */
export function generateEd25519KeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return generateKeyPairSync('ed25519');
}
