import { getSessionModel } from '@models/Session.model.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import type { Request, NextFunction } from 'express';
import mongoose from 'mongoose';

export async function listSessionsController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const { sub, sessionId } = res.locals.authenticatedUser;

      const sessions = await getSessionModel()
         .find(
            { userId: new mongoose.Types.ObjectId(sub) },
            // Projecting only what the client needs
            { _id: 1, ipAddress: 1, userAgent: 1, createdAt: 1, expiresAt: 1 }
         )
         .lean();

      // Annotate which one is "this" session so the frontend can mark it
      const result = sessions.map(s => ({
         ...s,
         isCurrent: s._id.toString() === sessionId,
      }));

      return void res.status(200).json({ success: true, sessions: result });
   } catch (err) {
      next(err);
   }
}
