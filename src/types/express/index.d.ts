import 'express';
import type { UserRole } from '@ssot/user_roles_constants.ts';

declare global {
   namespace Express {
      interface Locals {
         requestId: string;

         /* Optional because not every route is protected. The authenticate middleware guarantees this is present before calling next(), so any controller behind it can safely depend on its existence. */
         authenticatedUser?: {
            sub: string; // user._id as a string, matches the JWT `sub` claim
            role: UserRole;
            canIssueInvites: boolean;
         };
      }
   }
}
