import type { Request, NextFunction } from 'express';
import {
   getUserModel,
   type SafeUser,
   type PublicUser,
} from '@models/User.model.ts';
import {
   SAFE_USER_PROJECTION,
   PUBLIC_USER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';

export async function listUsersController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const { role } = res.locals.authenticatedUser;
      const isSuperAdmin = role === 'superadmin';
      const User = getUserModel();

      if (isSuperAdmin) {
         /* The superadmin sees everything except `passwordHash`. We're type-asserting because TypeScript cannot verify the projection at compile time. */
         const users = (await User.find(
            {},
            SAFE_USER_PROJECTION
         ).lean()) as SafeUser[];
         return void res.status(200).json({ success: true, users });
      }

      /* Non-superadmin users see the minimal public shape: name, email, role, and canIssueInvites. */
      const users = (await User.find(
         { invitedBy: { $exists: true } },
         PUBLIC_USER_PROJECTION
      ).lean()) as PublicUser[];
      return void res.status(200).json({ success: true, users });
   } catch (err) {
      next(err);
   }
}
