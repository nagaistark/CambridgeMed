import { DateTime } from 'luxon';
import { JWT_ACCESS_TOKEN_EXPIRY_MS } from '@ssot/access_refresh_tokens_constants.ts';
import { RESET_WEEKDAY } from '@ssot/date_time_constants.ts';

export function getMaxAgeTokens(): {
   ATMA: number;
   RTMA: number;
   ATEXP: number;
   RTEXP: number;
} {
   const now = DateTime.now(); // The "now" timestamp for Toronto, ON
   const daysUntilNextRTRWD = (RESET_WEEKDAY + 7 - now.weekday) % 7 || 7;

   // Refresh Token Reset Weekday => RTRWD
   const nextRTRWD = now.plus({ days: daysUntilNextRTRWD }).startOf('day');

   const nowUTC = Date.now();

   // refreshTokenMaxAge => RTMA
   const RTMA = nextRTRWD.diff(now).as('milliseconds');

   // accessTokenMaxAge => ATMA
   const ATMA = Math.min(JWT_ACCESS_TOKEN_EXPIRY_MS, RTMA);

   // refreshTokenExpirationTime => RTEXP
   const RTEXP = nowUTC + RTMA;

   // accessTokenExpirationTime => ATEXP
   const ATEXP = nowUTC + ATMA;

   return { ATMA, RTMA, ATEXP, RTEXP };
}
