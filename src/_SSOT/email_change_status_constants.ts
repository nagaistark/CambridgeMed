import type { IEmailChangeStatusSource } from '@models/EmailChange_v3.model.ts';

type Source = IEmailChangeStatusSource;

/* What the OWNER may know about an in-flight email change. Computed from the document, never stored. No token hashes, no _id. */
export type EmailChangeStatus =
   | { readonly state: 'none' }
   | {
        readonly state: 'pending';
        readonly newEmail: Source['newEmail'];
        readonly confirmExpiresAt: Source['confirmExpiresAt'];
     }
   | {
        readonly state: 'confirmed';
        readonly oldEmail: Source['oldEmail'];
        readonly newEmail: Source['newEmail'];
        readonly confirmedAt: NonNullable<Source['confirmedAt']>;
        readonly revertExpiresAt: Source['cancelExpiresAt'];
     };

/* The single definition of "active". The TTL janitor lags by up to a minute, so a document that still physically exists may already be dead; the clock decides, not existence. */
export function classifyEmailChange(
   change: IEmailChangeStatusSource,
   now: Date
): EmailChangeStatus {
   const nowMs = now.getTime();

   if (change.cancelExpiresAt.getTime() <= nowMs) return { state: 'none' };

   if (change.confirmedAt !== null) {
      return {
         state: 'confirmed',
         oldEmail: change.oldEmail,
         newEmail: change.newEmail,
         confirmedAt: change.confirmedAt,
         revertExpiresAt: change.cancelExpiresAt,
      };
   }

   if (change.confirmExpiresAt.getTime() <= nowMs) return { state: 'none' };

   return {
      state: 'pending',
      newEmail: change.newEmail,
      confirmExpiresAt: change.confirmExpiresAt,
   };
}
