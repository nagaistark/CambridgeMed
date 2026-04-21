import type { SafeUser, PublicUser } from '@models/User.model.ts';

/* Field projections defined once at module level. Using MongoDB-level projection means `passwordHash` never travels over the wire from MongoDB to the Node process. */
export const SAFE_USER_PROJECTION: Record<keyof SafeUser, 1> = {
   // Annotated with SafeUser, which excludes (doesn't list) `passwordHash`.
   email: 1,
   firstName: 1,
   lastName: 1,
   role: 1,
   canIssueInvites: 1,
   previousNames: 1,
   previousEmails: 1,
   nameChangesUsed: 1,
   emailChangesUsed: 1,
   invitedBy: 1,
   isActive: 1,
   _id: 1,
   createdAt: 1,
   updatedAt: 1,
} as const;

export const PUBLIC_USER_PROJECTION: Record<keyof PublicUser, 1> = {
   _id: 1,
   firstName: 1,
   lastName: 1,
   email: 1,
   role: 1,
   canIssueInvites: 1,
} as const;
