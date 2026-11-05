import { DateTime } from 'luxon';
import { JWT_ACCESS_TOKEN_EXPIRY_MS } from '@ssot/access_refresh_tokens_constants.ts';
import { RESET_WEEKDAY } from '@ssot/date_time_constants.ts';

export function getMaxAgeTokens(now: Date): {
   accessTokenMaxAgeMS: number;
   refreshTokenMaxAgeMS: number;
   accessTokenExpirationTimestampMS: number;
   nextWeeklyResetTimestampMS: number; // <-- the moment both refresh token and invite expire
} {
   /* fromJSDate places the instant in Settings.defaultZone (America/Toronto), so the "next Monday 00:00" boundary is still computed in clinic time, exactly as before. */
   const nowInClinicZone = DateTime.fromJSDate(now);

   /* An invalid Date would make `weekday` NaN and poison every number below. Failing loudly beats minting tokens that expire at NaN. */
   if (!nowInClinicZone.isValid) {
      throw new RangeError(`getMaxAgeTokens received an invalid Date.`);
   }

   /* Luxon-based weekdays represented by a number: 1 — Monday, 7 — Sunday. */
   const daysUntilNextRefreshTokenResetWeekday =
      (RESET_WEEKDAY + 7 - nowInClinicZone.weekday) % 7 || 7;

   /* Refresh Token Reset Weekday - a Luxon DateTime object pointing at the very beginning of the next Reset Weekday. */
   const nextRefreshTokenResetWeekday = nowInClinicZone
      .plus({ days: daysUntilNextRefreshTokenResetWeekday })
      .startOf('day');

   /* refreshTokenMaxAge — The maximum duration (in milliseconds) that the overall user SESSION can last before requiring a hard re-authentication. Due to Refresh Token Rotation, an individual refresh token's actual lifespan is short-lived (invalidated upon its first use/rotation). This value represents the absolute hard stop or "ceiling" for the rotated token chain, aligning with our weekly reset policy */
   const refreshTokenMaxAgeMS = nextRefreshTokenResetWeekday
      .diff(nowInClinicZone)
      .as('milliseconds');

   /* accessTokenMaxAge — Normally, the `JWT_ACCESS_TOKEN_EXPIRY_MS` constant's value, but theoretically can be a less if, for example, issued on Sunday at 23:59:01 */
   const accessTokenMaxAgeMS = Math.min(
      JWT_ACCESS_TOKEN_EXPIRY_MS,
      refreshTokenMaxAgeMS
   );

   return {
      accessTokenMaxAgeMS,
      refreshTokenMaxAgeMS,
      accessTokenExpirationTimestampMS: now.getTime() + accessTokenMaxAgeMS, //  accessTokenExpirationTime — a point in time (Epoch) when access token naturally expires.
      nextWeeklyResetTimestampMS: now.getTime() + refreshTokenMaxAgeMS, // refreshTokenExpirationTime — a point in time (Epoch) when refresh token (or SESSION) naturally expires.
   };
}
