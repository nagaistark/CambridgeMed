import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import { myEnv } from '@/validateConfig.ts';

// ====================================================================================
// JWT KEY VALIDATION
// ====================================================================================
/* A lightweight sign-and-verify round-trip to confirm two things before the server accepts any traffic:
   1. Both PEM strings are cryptographically valid (not just well-formatted)
   2. The private and public keys actually form a matching pair
This is intentionally separate from validateConfig.ts, which can only check that the PEM envelope looks correct — it cannot verify the key mathematics. */
export async function validateJwtKeys(): Promise<void> {
   // The first layer of the check. `importPKCS8 / importSPKI` will throw if the Base64 content inside the PEM envelope is malformed, even if the headers looked fine.
   const privateKey = await importPKCS8(myEnv.jwt.privateKey, 'RS256');
   const publicKey = await importSPKI(myEnv.jwt.publicKey, 'RS256');

   // The second layer of the check: signing a minimal throwaway payload and setting a very short expirty because this token in never used for anything real.
   const testToken = await new SignJWT({ sub: 'jwt-key-validation-check' })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime('30s')
      .sign(privateKey);

   // If the keys don't form a matching pair, `jwtVeriry` throws here.
   await jwtVerify(testToken, publicKey, { algorithms: ['RS256'] });
}
