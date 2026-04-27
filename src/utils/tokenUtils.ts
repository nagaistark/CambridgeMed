import { SignJWT } from 'jose';
import type { Response } from 'express';
import { myEnv } from 'validateConfig.ts';
import type { UserRole } from '@ssot/user_roles_constants.ts';
import { getPrivateKey } from '@utils/jwtUtils.ts';
import {
   generateRandomToken,
   generateStandardHash,
} from '@ssot/node_crypto_constants.ts';

// ── Constants ────────────────────────────────────────────────────────────────
// Single source of truth for cookie names. Imported by the authenticate middleware and the refresh controller.
export const ACCESS_TOKEN_COOKIE_NAME = 'access_token' as const;
export const REFRESH_TOKEN_COOKIE_NAME = 'refresh_token' as const;

// The audience claim embedded in every access token. jwtVerify in the authenticate middleware must specify this value, which prevents email verification tokens from ever being used as access tokens.
export const ACCESS_TOKEN_AUDIENCE = 'access' as const;

// ── Access token ─────────────────────────────────────────────────────────────
export type AccessTokenPayload = {
   sub: string; // user._id as a string
   role: UserRole;
   canIssueInvites: boolean;
   expirationTime: number;
};

export async function signAccessToken(
   payload: AccessTokenPayload
): Promise<string> {
   const privateKey = await getPrivateKey(); // Here, we use the module-level cache in jwtUtils
   return new SignJWT({
      role: payload.role,
      canIssueInvites: payload.canIssueInvites,
   })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(payload.sub)
      .setAudience(ACCESS_TOKEN_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(Math.floor(payload.expirationTime / 1000)) // Unix Timestamps. Should be SECONDS (not milliseconds) since THE EPOCH!!!
      .sign(privateKey);
}

// ── Refresh token ────────────────────────────────────────────────────────────
// Generating a cryptographically random opaque token plus its SHA-256 hash. The `raw` value goes to the client as an httpOnly cookie. The `hash` value is what we store in MongoDB.
export function generateRefreshToken(): { raw: string; hash: string } {
   const raw = generateRandomToken();
   const hash = generateStandardHash(raw);
   return { raw, hash };
}

// ── Cookie management ────────────────────────────────────────────────────────
const isProduction = myEnv.environment === 'production';
export function setAuthCookies(
   res: Response,
   accessToken: string,
   accessTokenMaxAge: number,
   rawRefreshToken: string,
   RefreshTokenMaxAge: number
): void {
   const sameSite: 'none' | 'lax' = isProduction ? 'none' : 'lax';

   res.cookie(ACCESS_TOKEN_COOKIE_NAME, accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite,
      maxAge: accessTokenMaxAge,
      path: '/api',
   });

   // Refresh token is scoped to /api/auth only. The browser will never send it to /api/patients, /api/users, or anywhere else. Even if we accidentally try to read it there.
   res.cookie(REFRESH_TOKEN_COOKIE_NAME, rawRefreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite,
      maxAge: RefreshTokenMaxAge,
      path: '/api/auth',
   });
}

export function clearAuthCookies(res: Response): void {
   const sameSite: 'none' | 'lax' = isProduction ? 'none' : 'lax';

   // clearCookie works by issuing a Set-Cookie header with an expired date. The path must match exactly what was used when setting or the browser won't find the cookie to delete.
   res.clearCookie(ACCESS_TOKEN_COOKIE_NAME, {
      httpOnly: true,
      secure: isProduction,
      sameSite,
      path: '/api',
   });

   res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, {
      httpOnly: true,
      secure: isProduction,
      sameSite,
      path: '/api/auth',
   });
}
