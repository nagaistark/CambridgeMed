import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import { myEnv } from '@/validateConfig.ts';

//== JWT KEY VALIDATION ────────────────────────────────────────────────────────────────
/* Confirming two things before the server accepts any traffic:
   1. Both PEM strings are cryptographically valid (not just well-formatted)
   2. The private and public keys actually form a matching pair
We do the validation once and hold the resulting CryptoKey objects in module scope for the lifetime of the process. */
let _cachedPrivateKey: CryptoKey | null = null;
let _cachedPublicKey: CryptoKey | null = null;

export async function getPrivateKey(): Promise<CryptoKey> {
   if (!_cachedPrivateKey) {
      _cachedPrivateKey = await importPKCS8(myEnv.jwt.privateKey, 'RS256');
   }
   return _cachedPrivateKey;
}

export async function getPublicKey(): Promise<CryptoKey> {
   if (!_cachedPublicKey) {
      _cachedPublicKey = await importSPKI(myEnv.jwt.publicKey, 'RS256');
   }
   return _cachedPublicKey;
}

//== STARTUP VALIDATOR ────────────────────────────────────────────────────────────────
export async function validateJwtKeys(): Promise<void> {
   // Called once during server bootstrap. After this succeeds, the keys are warmed in cache and every subsequent sign/verify is near-instant.
   const privateKey = await getPrivateKey();
   const publicKey = await getPublicKey();

   // The second layer of the check: signing a minimal throwaway payload and setting a very short expirty because this token in never used for anything real.
   const testToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime('30s')
      .sign(privateKey);

   // If the keys don't form a matching pair, `jwtVeriry` throws here.
   await jwtVerify(testToken, publicKey, { algorithms: ['RS256'] });
}
