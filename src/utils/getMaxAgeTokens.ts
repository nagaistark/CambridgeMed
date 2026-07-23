import { DateTime } from 'luxon';
import { JWT_ACCESS_TOKEN_EXPIRY_MS } from '@ssot/access_refresh_tokens_constants.ts';
import { RESET_WEEKDAY } from '@ssot/date_time_constants.ts';

export function getMaxAgeTokens(): {
   accessTokenMaxAgeMS: number;
   refreshTokenMaxAgeMS: number;
   accessTokenExpirationTimestampMS: number;
   refreshTokenExpirationTimestampMS: number;
} {
   /* The Single Source of Truth for "now" (in Toronto, but it really doesn't matter because we derive Epoch timestamp from it) represented by a Luxon DateTime object within the scope of the function. */
   const now = DateTime.now();

   /* Luxon-based weekdays represented by a number: 1 — Monday, 7 — Sunday. */
   const daysUntilNextRefreshTokenResetWeekday =
      (RESET_WEEKDAY + 7 - now.weekday) % 7 || 7;

   /* Refresh Token Reset Weekday - a Luxon DateTime object pointing at the very beginning of the next Reset Weekday. */
   const nextRefreshTokenResetWeekday = now
      .plus({ days: daysUntilNextRefreshTokenResetWeekday })
      .startOf('day');

   /* refreshTokenMaxAge — The maximum duration (in milliseconds) that the overall user SESSION can last before requiring a hard re-authentication. Due to Refresh Token Rotation, an individual refresh token's actual lifespan is short-lived (invalidated upon its first use/rotation). This value represents the absolute hard stop or "ceiling" for the rotated token chain, aligning with our weekly reset policy */
   const refreshTokenMaxAgeMS = nextRefreshTokenResetWeekday
      .diff(now)
      .as('milliseconds');

   /* accessTokenMaxAge — Normally, the `JWT_ACCESS_TOKEN_EXPIRY_MS` constant's value, but theoretically can be a less if, for example, issued on Sunday at 23:59:01 */
   const accessTokenMaxAgeMS = Math.min(
      JWT_ACCESS_TOKEN_EXPIRY_MS,
      refreshTokenMaxAgeMS
   );

   /* refreshTokenExpirationTime — a point in time (Epoch) when refresh token (or SESSION) naturally expires. */
   const refreshTokenExpirationTimestampMS =
      now.toMillis() + refreshTokenMaxAgeMS;

   /* accessTokenExpirationTime — a point in time (Epoch) when access token naturally expires. */
   const accessTokenExpirationTimestampMS =
      now.toMillis() + accessTokenMaxAgeMS;

   return {
      accessTokenMaxAgeMS,
      refreshTokenMaxAgeMS,
      accessTokenExpirationTimestampMS,
      refreshTokenExpirationTimestampMS,
   };
}
