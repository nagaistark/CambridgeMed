import type { Request, NextFunction } from 'express';
import { getSessionCollection } from '@models/Session_v3.model.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { ObjectId } from 'mongodb';

type KillSessionParams = { id: string };

export async function killSessionController(
   req: Request<KillSessionParams>,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const {
         sub,
         role,
         sessionId: currentSessionId,
      } = res.locals.authenticatedUser;
      const isSuperAdmin = role === 'superadmin';

      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Invalid session ID.`,
                  requestId
               )
            );
      }

      // Refuse self-termination. That's what logout is for
      if (id === currentSessionId) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Use the logout endpoint to terminate your current session.`,
                  requestId
               )
            );
      }

      const sessionCollection = getSessionCollection();

      const targetSession = await sessionCollection.findOne({
         _id: new ObjectId(id),
      });

      if (
         !targetSession ||
         (!isSuperAdmin && targetSession.userId.toString() !== sub)
      ) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', 'Session not found.', requestId)
            );
      }

      // ── Recency enforcement (non-superadmin users) ─────────────────────────────
      /* We only allow killing sessions that were created AFTER the current one. */
      if (!isSuperAdmin) {
         const currentSession = await sessionCollection.findOne({
            _id: new ObjectId(currentSessionId),
         });
         if (!currentSession) {
            // If the current session has somehow vanished, treat it as expired
            return void res
               .status(401)
               .json(
                  createErrorResponse(
                     'UNAUTHORIZED',
                     `Current session not found.`,
                     requestId
                  )
               );
         }

         if (targetSession.createdAt < currentSession.createdAt) {
            return void res
               .status(403)
               .json(
                  createErrorResponse(
                     'FORBIDDEN',
                     `You can only terminate sessions that were created after your current session.`,
                     requestId
                  )
               );
         }
      }

      await sessionCollection.deleteOne({ _id: targetSession._id });

      return void res.status(200).json({
         success: true,
         message: `Session terminated successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
