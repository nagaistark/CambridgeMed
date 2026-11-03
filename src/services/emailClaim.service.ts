import type { CountDocumentsOptions } from 'mongodb';
import {
   getUserCollection,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import {
   getInviteCollection,
   type IInviteDocumentRead,
} from '@models/Invite_v3.model.ts';
import {
   getEmailChangeCollection,
   type IEmailChangeDocumentRead,
} from '@models/EmailChange_v3.model.ts';
import type { StrictMongoFilter } from '@utils/pathFinder_v3.ts';

export type EmailClaim =
   'user' | 'invite' | 'pending_email_change' | 'revertable_email_change';

/* The single definition of "is this address spoken for right now?". To the future me: these are four independent reads, not a SNAPSHOT! The unique index on `users.email` remains the arbiter at commit time. */
export async function findEmailClaim(
   email: IUserDocument['email'],
   now: Date
): Promise<EmailClaim | null> {
   const [users, invites, pendingChanges, revertableChanges] =
      await Promise.all([
         getUserCollection().countDocuments(
            { email } satisfies StrictMongoFilter<IUserDocument>,
            { limit: 1 } satisfies CountDocumentsOptions
         ),
         getInviteCollection().countDocuments(
            {
               email,
               usedAt: null,
               expiresAt: { $gt: now },
            } satisfies StrictMongoFilter<IInviteDocumentRead>,
            { limit: 1 } satisfies CountDocumentsOptions
         ),
         getEmailChangeCollection().countDocuments(
            {
               newEmail: email,
               confirmedAt: null,
               confirmExpiresAt: { $gt: now },
            } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
            { limit: 1 } satisfies CountDocumentsOptions
         ),
         getEmailChangeCollection().countDocuments(
            {
               oldEmail: email,
               confirmedAt: { $ne: null },
               cancelExpiresAt: { $gt: now },
            } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
            { limit: 1 } satisfies CountDocumentsOptions
         ),
      ]);

   if (users > 0) return 'user';
   if (invites > 0) return 'invite';
   if (pendingChanges > 0) return 'pending_email_change';
   if (revertableChanges > 0) return 'revertable_email_change';
   return null;
}
