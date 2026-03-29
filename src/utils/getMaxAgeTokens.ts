import { DateTime, Settings } from 'luxon';
Settings.defaultLocale = 'en-CA';
Settings.defaultZone = 'America/Toronto';
import {
   JWT_ACCESS_TOKEN_EXPIRY_MS,
   JWT_REFRESH_TOKEN_RESET_WEEKDAY,
} from '@ssot/access_refresh_tokens_constants.ts';

export function getMaxAgeTokens(): {
   ATMA: number;
   RTMA: number;
   ATEXP: number;
   RTEXP: number;
} {
   const now = DateTime.now(); // The "now" timestamp for Toronto, ON
   const daysUntilNextRTRWD =
      (JWT_REFRESH_TOKEN_RESET_WEEKDAY + 7 - now.weekday) % 7 || 7;

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
