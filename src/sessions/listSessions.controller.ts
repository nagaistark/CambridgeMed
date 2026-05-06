import { getSessionModel } from '@models/Session.model.ts';
import { getUserModel } from '@models/User.model.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import type { Request, NextFunction } from 'express';
import mongoose from 'mongoose';

export async function listSessionsController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const { sub, role, sessionId } = res.locals.authenticatedUser;
      const isSuperAdmin = role === 'superadmin';
      const Session = getSessionModel();

      // The superadmin case: fetching ALL sessions across all users
      if (isSuperAdmin) {
         const sessions = await Session.find(
            {},
            {
               _id: 1,
               userId: 1,
               ipAddress: 1,
               userAgent: 1,
               createdAt: 1,
               expiresAt: 1,
            }
         ).lean();

         if (sessions.length === 0) {
            return void res.status(200).json({ success: true, sessions: [] });
         }

         // Batch-fetching user identity for display purposes (same pattern as in the listInvitesController)
         const uniqueUserIds = [
            ...new Set(sessions.map(s => s.userId.toString())),
         ];

         const users = await getUserModel()
            .find(
               { _id: { $in: uniqueUserIds } },
               { _id: 1, firstName: 1, lastName: 1, email: 1 }
            )
            .lean();

         const userMap = new Map(users.map(u => [u._id.toString(), u]));

         const result = sessions.map(s => ({
            ...s,
            isCurrent: s._id.toString() === sessionId,
            user: userMap.get(s.userId.toString()) ?? null,
         }));

         return void res.status(200).json({ success: true, sessions: result });
      }

      // The regular user case:
      const sessions = await Session.find(
         { userId: new mongoose.Types.ObjectId(sub) },
         { _id: 1, ipAddress: 1, userAgent: 1, createdAt: 1, expiresAt: 1 }
      ).lean();

      const result = sessions.map(s => ({
         ...s,
         isCurrent: s._id.toString() === sessionId,
      }));

      return void res.status(200).json({ success: true, sessions: result });
   } catch (err) {
      next(err);
   }
}
