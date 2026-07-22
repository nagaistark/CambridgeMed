import { getSessionCollection } from '@models/Session_v3.model.ts';
import { getUserCollection } from '@models/User_v3.model.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import type { Request, NextFunction } from 'express';
import { ObjectId } from 'mongodb';

export async function listSessionsController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const { sub, role, sessionId } = res.locals.authenticatedUser;
      const isSuperAdmin = role === 'superadmin';
      const sessionCollection = getSessionCollection();

      // The superadmin case: fetching ALL sessions across all users
      if (isSuperAdmin) {
         const sessions = await sessionCollection
            .find(
               {},
               {
                  projection: {
                     _id: 1,
                     userId: 1,
                     ipAddress: 1,
                     userAgent: 1,
                     createdAt: 1,
                     expiresAt: 1,
                  },
               }
            )
            .toArray();

         if (sessions.length === 0) {
            return void res.status(200).json({ success: true, sessions: [] });
         }

         // Batch-fetching user identity for display purposes (same pattern as in the listInvitesController)
         const uniqueUserIds = [...new Set(sessions.map(s => s.userId))];

         const users = await getUserCollection()
            .find(
               { _id: { $in: uniqueUserIds } },
               { projection: { _id: 1, firstName: 1, lastName: 1, email: 1 } }
            )
            .toArray();

         const userMap = new Map(users.map(u => [u._id.toString(), u]));

         const result = sessions.map(s => ({
            ...s,
            isCurrent: s._id.toString() === sessionId,
            user: userMap.get(s.userId.toString()) ?? null,
         }));

         return void res.status(200).json({ success: true, sessions: result });
      }

      // The regular user case:
      const sessions = await sessionCollection
         .find(
            { userId: new ObjectId(sub) },
            {
               projection: {
                  _id: 1,
                  ipAddress: 1,
                  userAgent: 1,
                  createdAt: 1,
                  expiresAt: 1,
               },
            }
         )
         .toArray();

      const result = sessions.map(s => ({
         ...s,
         isCurrent: s._id.toString() === sessionId,
      }));

      return void res.status(200).json({ success: true, sessions: result });
   } catch (err) {
      next(err);
   }
}
