import { SignJWT } from 'jose';
import type { Response } from 'express';
import { myEnv } from 'validateConfig.ts';
import type { UserRole } from '@ssot/user_roles_constants.ts';
import { getPrivateKey } from '@utils/jwtUtils.ts';
import {
   generateRandomToken,
   generateStandardHash,
} from '@ssot/node_crypto_constants.ts';
import {
   TOTP_CHALLENGE_AUDIENCE,
   TOTP_CHALLENGE_COOKIE_NAME,
   TOTP_CHALLENGE_EXPIRY_SECONDS,
} from '@ssot/totp_constants.ts';

// ── Constants ────────────────────────────────────────────────────────────────────
/* Single source of truth for cookie names. Imported by the authenticate middleware and the refresh controller. */
export const ACCESS_TOKEN_COOKIE_NAME = 'access_token' as const;
export const REFRESH_TOKEN_COOKIE_NAME = 'refresh_token' as const;

/* The audience claim embedded in every access token. jwtVerify in the authenticate middleware must specify this value, which prevents email verification tokens from ever being used as access tokens. */
export const ACCESS_TOKEN_AUDIENCE = 'access' as const;

// ── Access token ─────────────────────────────────────────────────────────────────
export type AccessTokenPayload = {
   sub: string; // user._id as a string
   role: UserRole;
   canIssueInvites: boolean;
   sessionId: string; // the Session document's _id as a string
   expirationTime: number;
};

export async function signAccessToken(
   payload: AccessTokenPayload
): Promise<string> {
   const privateKey = await getPrivateKey(); // Here, we use the module-level cache in jwtUtils
   return new SignJWT({
      role: payload.role,
      canIssueInvites: payload.canIssueInvites,
      sessionId: payload.sessionId,
   })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(payload.sub)
      .setAudience(ACCESS_TOKEN_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(Math.floor(payload.expirationTime / 1000)) // Unix Timestamps. Should be SECONDS (not milliseconds) since THE EPOCH!!!
      .sign(privateKey);
}

// ── Refresh token ────────────────────────────────────────────────────────────────
/* Generating a cryptographically random opaque token plus its SHA-256 hash. The `raw` value goes to the client as an httpOnly cookie. The `hash` value is what we store in MongoDB. */
export function generateRefreshToken(): { raw: string; hash: string } {
   const raw = generateRandomToken();
   const hash = generateStandardHash(raw);
   return { raw, hash };
}

// ── Cookie management ────────────────────────────────────────────────────────────
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

   /* Refresh token is scoped to /api/auth only. The browser will never send it to /api/patients, /api/users, or anywhere else. Even if we accidentally try to read it there. */
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

   /* clearCookie works by issuing a Set-Cookie header with an expired date. The path must match exactly what was used when setting or the browser won't find the cookie to delete. */
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

// ── TOTP challenge token ─────────────────────────────────────────────────────────
/* A narrow-scope, short-lived JWT issued after a successful password check when the user has TOTP enabled. It is the "you're halfway there" ticket. The audience claim ensures it is rejected by every route except /totp/verify and /totp/recover. It carries only `sub` — there's nothing else we need to know at the TOTP verification stage. */
export async function signTotpChallengeToken(userId: string): Promise<string> {
   const privateKey = await getPrivateKey();
   return new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(userId)
      .setAudience(TOTP_CHALLENGE_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(`${TOTP_CHALLENGE_EXPIRY_SECONDS}s`)
      .sign(privateKey);
}

export function setTotpChallengeCookie(res: Response, token: string): void {
   const sameSite: 'none' | 'lax' = isProduction ? 'none' : 'lax';
   res.cookie(TOTP_CHALLENGE_COOKIE_NAME, token, {
      httpOnly: true,
      secure: isProduction,
      sameSite,
      maxAge: TOTP_CHALLENGE_EXPIRY_SECONDS * 1000,
      path: '/api/auth/totp', // Scoped tightly — never sent outside this subtree
   });
}

export function clearTotpChallengeCookie(res: Response): void {
   const sameSite: 'none' | 'lax' = isProduction ? 'none' : 'lax';
   res.clearCookie(TOTP_CHALLENGE_COOKIE_NAME, {
      httpOnly: true,
      secure: isProduction,
      sameSite,
      path: '/api/auth/totp',
   });
}
