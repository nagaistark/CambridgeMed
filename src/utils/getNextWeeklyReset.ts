import { DateTime } from 'luxon';
import { RESET_WEEKDAY } from '@ssot/date_time_constants.ts';

/* The next weekly reset boundary (the coming RESET_WEEKDAY at 00:00, clinic time), strictly in the future: on the reset day itself the answer is a week away. Shared by session lifetime and invite expiry, so the two can never drift apart. */
export function getNextWeeklyReset(now: Date): Date {
   /* fromJSDate places the instant in Settings.defaultZone (America/Toronto), so the boundary is computed in clinic time. */
   const nowInClinicZone = DateTime.fromJSDate(now);

   /* An invalid Date would make `weekday` NaN and poison everything downstream. Failing loudly beats minting credentials that expire at NaN. */
   if (!nowInClinicZone.isValid) {
      throw new RangeError(`getNextWeeklyReset received an invalid Date.`);
   }

   /* Luxon weekdays: 1 — Monday, 7 — Sunday. */
   const daysUntilReset =
      (RESET_WEEKDAY + 7 - nowInClinicZone.weekday) % 7 || 7;

   /* Calendar arithmetic (not "+ 24h * n"), so a DST change inside the week cannot shift the boundary off midnight. */
   const reset = nowInClinicZone.plus({ days: daysUntilReset }).startOf('day');

   if (!reset.isValid) {
      throw new RangeError(`getNextWeeklyReset produced an invalid boundary.`);
   }

   return reset.toJSDate();
}
