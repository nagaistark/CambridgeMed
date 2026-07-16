import type { Request, NextFunction } from 'express';
import { getUserCollection } from '@models/User_v3.model.ts';
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
      const userCollection = getUserCollection();

      if (isSuperAdmin) {
         /* The superadmin sees everything except `passwordHash`. We're type-asserting because TypeScript cannot verify the projection at compile time. */
         const users = await userCollection
            .find({}, { projection: SAFE_USER_PROJECTION })
            .toArray();
         return void res.status(200).json({ success: true, users });
      }

      /* Non-superadmin users see the minimal public shape: name, email, role, and permissions. */
      const users = await userCollection
         .find(
            { invitedBy: { $exists: true } },
            { projection: PUBLIC_USER_PROJECTION }
         )
         .toArray();
      return void res.status(200).json({ success: true, users });
   } catch (err) {
      next(err);
   }
}
