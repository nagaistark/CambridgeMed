import type { Request, Response } from 'express';
import {
   generateRandomToken,
   generateStandardHash,
   HEX96_REGEX,
} from '@ssot/node_crypto_constants.ts';
import {
   TOTP_CHALLENGE_COOKIE_NAME,
   TOTP_CHALLENGE_EXPIRY_SECONDS,
} from '@ssot/totp_constants.ts';

// ── Constants ────────────────────────────────────────────────────────────────────
/* Single source of truth for the session cookie name. The `__Host-` prefix is enforced by the BROWSER: it will only accept this cookie if it is `Secure`, has `Path=/` and carries no `Domain`. That stops a sibling subdomain or an insecure origin from planting a cookie of this name (a session-fixation vector). */
export const SESSION_COOKIE_NAME = '__Host-sid' as const;

// ── Session token ────────────────────────────────────────────────────────────────
/* A cryptographically random opaque token plus its SHA-256 hash. The `raw` value goes to the browser as an httpOnly cookie. Only the `hash` is stored. The token is always minted by the SERVER: a client can never choose its own session identifier. */
export function generateSessionToken(): { raw: string; hash: string } {
   const raw = generateRandomToken();
   const hash = generateStandardHash(raw);
   return { raw, hash };
}

/* req.cookies is `any` (and cookie-parser turns `j:{...}` cookies into OBJECTS). Reading through `unknown` forces a real runtime check instead of an implicit cast. */
function readStringCookie(req: Request, name: string): string | undefined {
   const value: unknown = req.cookies[name];
   return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/* The token has a known shape, so junk is rejected before it costs a hash or a DB hit. */
export function readSessionTokenCookie(req: Request): string | undefined {
   const value = readStringCookie(req, SESSION_COOKIE_NAME);
   return value !== undefined && HEX96_REGEX.test(value) ? value : undefined;
}

// ── Private cookie primitives ────────────────────────────────────────────────────
/* Not exported. They encode the security baseline that every cookie in this application must meet, so the flags are defined in exactly one place. `secure: true` in EVERY environment (dev runs behind HTTPS too), which is also what the `__Host-` prefix requires. */
function writeCookie(
   res: Response,
   name: string,
   value: string,
   maxAge: number,
   path: string
): void {
   res.cookie(name, value, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge,
      path,
   });
}

/* A cookie is erased by re-sending it with the SAME attributes and an expiry in the past. For a `__Host-` cookie the browser rejects the erasure unless `Secure` and `Path=/` match. */
function eraseCookie(res: Response, name: string, path: string): void {
   res.clearCookie(name, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path,
   });
}

// ── Public cookie functions ──────────────────────────────────────────────────────
/* `maxAgeMs` is the time left until the session's ABSOLUTE expiry, never longer: the cookie can outlive an idle logoff (the server decides that), but never the weekly reset. Not re-sent when the idle timer slides. */
export function setSessionCookie(
   res: Response,
   rawToken: string,
   maxAgeMs: number
): void {
   if (!Number.isFinite(maxAgeMs) || maxAgeMs <= 0) {
      throw new RangeError(`Session cookie maxAge must be a positive number.`);
   }
   writeCookie(res, SESSION_COOKIE_NAME, rawToken, maxAgeMs, '/');
}

/* Kept under its old name to avoid touching five call sites (logout, password change/reset, email confirm/cancel). It now clears the single session cookie. */
export function clearAuthCookies(res: Response): void {
   eraseCookie(res, SESSION_COOKIE_NAME, '/');
}

// ── TOTP challenge cookie ────────────────────────────────────────────────────────
/* The challenge is an opaque server-side record, exactly like the session (see totpChallenge.ts). Same baseline: `__Host-`, Secure, HttpOnly, SameSite=Strict, Path=/. Path scoping to /api/auth/totp is given up (the `__Host-` prefix requires Path=/); the cookie lives 5 minutes, is single-use, and is useless without the second factor. */
export function setTotpChallengeCookie(res: Response, rawToken: string): void {
   writeCookie(
      res,
      TOTP_CHALLENGE_COOKIE_NAME,
      rawToken,
      TOTP_CHALLENGE_EXPIRY_SECONDS * 1000,
      '/'
   );
}

export function clearTotpChallengeCookie(res: Response): void {
   eraseCookie(res, TOTP_CHALLENGE_COOKIE_NAME, '/');
}

/* Same shape check as the session cookie: junk is rejected before it costs a hash or a DB hit. */
export function readTotpChallengeCookie(req: Request): string | undefined {
   const value = readStringCookie(req, TOTP_CHALLENGE_COOKIE_NAME);
   return value !== undefined && HEX96_REGEX.test(value) ? value : undefined;
}
