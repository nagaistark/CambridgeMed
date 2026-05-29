import { SignJWT } from 'jose';
import type { Response } from 'express';
import { myEnv } from 'validateConfig.ts';
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
import { AuthenticatedUser } from '@ssot/authenticated_user_constants.ts';

// ── Constants ────────────────────────────────────────────────────────────────────
/* Single source of truth for cookie names. Imported by the authenticate middleware and the refresh controller. */
export const ACCESS_TOKEN_COOKIE_NAME = 'access_token' as const;
export const REFRESH_TOKEN_COOKIE_NAME = 'refresh_token' as const;

/* The audience claim embedded in every access token. jwtVerify in the authenticate middleware must specify this value, which prevents email verification tokens from ever being used as access tokens. */
export const ACCESS_TOKEN_AUDIENCE = 'access' as const;

// ── Access token ─────────────────────────────────────────────────────────────────
export type AccessTokenPayload = AuthenticatedUser & {
   expirationTime: number;
};

export async function signAccessToken(
   payload: AccessTokenPayload
): Promise<string> {
   const privateKey = await getPrivateKey(); // Here, we use the module-level cache in jwtUtils
   return new SignJWT({
      role: payload.role,
      permissions: payload.permissions,
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

// ── Private cookie primitives ────────────────────────────────────────────────────
/* These are not exported. They encode the security baseline that every cookie in this application must meet. All public cookie functions delegate to these so the security flags are defined in exactly one place. */
function writeCookie(
   res: Response,
   name: string,
   value: string,
   maxAge: number,
   path: string
): void {
   const sameSite: 'none' | 'lax' = isProduction ? 'none' : 'lax';
   res.cookie(name, value, {
      httpOnly: true,
      secure: isProduction,
      sameSite,
      maxAge,
      path,
   });
}

function eraseCookie(res: Response, name: string, path: string): void {
   const sameSite: 'none' | 'lax' = isProduction ? 'none' : 'lax';
   res.clearCookie(name, {
      httpOnly: true,
      secure: isProduction,
      sameSite,
      path,
   });
}

// ── Cookie management ────────────────────────────────────────────────────────────
const isProduction = myEnv.environment === 'production';

// ── Public cookie functions ──────────────────────────────────────────────────────
export function setAuthCookies(
   res: Response,
   accessToken: string,
   accessTokenMaxAge: number,
   rawRefreshToken: string,
   refreshTokenMaxAge: number
): void {
   writeCookie(
      res,
      ACCESS_TOKEN_COOKIE_NAME,
      accessToken,
      accessTokenMaxAge,
      '/api'
   );
   writeCookie(
      res,
      REFRESH_TOKEN_COOKIE_NAME,
      rawRefreshToken,
      refreshTokenMaxAge,
      '/api/auth'
   );
}

export function clearAuthCookies(res: Response): void {
   eraseCookie(res, ACCESS_TOKEN_COOKIE_NAME, '/api');
   eraseCookie(res, REFRESH_TOKEN_COOKIE_NAME, '/api/auth');
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
   writeCookie(
      res,
      TOTP_CHALLENGE_COOKIE_NAME,
      token,
      TOTP_CHALLENGE_EXPIRY_SECONDS * 1000,
      '/api/auth/totp'
   );
}

export function clearTotpChallengeCookie(res: Response): void {
   eraseCookie(res, TOTP_CHALLENGE_COOKIE_NAME, '/api/auth/totp');
}
