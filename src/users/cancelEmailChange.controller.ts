import type { Request, Response, NextFunction } from 'express';
import {
   getUserCollection,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import {
   EmailChangeDocumentReadValidator,
   getEmailChangeCollection,
   type IEmailChangeDocumentRead,
} from '@models/EmailChange_v3.model.ts';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import {
   getPasswordResetCollection,
   type IPasswordResetDocumentRead,
} from '@models/PasswordReset_v3.model.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import type { ClientSession, ObjectId } from 'mongodb';
import { requestContext, securityLog } from '@services/securityLog.service.ts';

type CancelParams = { token: string };
type CancelOutcome =
   | { status: 'invalid' }
   | { status: 'cancelled'; userId: ObjectId }
   | { status: 'reverted'; userId: ObjectId };

async function runCancelTransaction(
   session: ClientSession,
   tokenHash: string
): Promise<CancelOutcome> {
   return session.withTransaction(async (): Promise<CancelOutcome> => {
      const now = new Date();

      const deletedRaw = await getEmailChangeCollection().findOneAndDelete(
         {
            cancelTokenHash: tokenHash,
            cancelExpiresAt: { $gt: now },
         } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
         { session }
      );
      if (deletedRaw === null) return { status: 'invalid' };

      const decoded = Schema.decodeUnknownEither(
         EmailChangeDocumentReadValidator
      )(deletedRaw);
      if (Either.isLeft(decoded)) throw decoded.left;
      const change = decoded.right;

      if (change.confirmedAt === null)
         return { status: 'cancelled', userId: change.userId };

      const archived: IUserDocument['previousEmails'][number] = {
         email: change.oldEmail,
         archivedAt: change.confirmedAt,
      };

      const reverted = await getUserCollection().updateOne(
         {
            _id: change.userId,
            email: change.newEmail,
            emailChangesUsed: { $gt: 0 },
            previousEmails: { $elemMatch: archived },
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: {
               email: change.oldEmail,
               passwordResetRequired: true,
               updatedAt: now,
            },
            $pull: { previousEmails: archived },
            $inc: { emailChangesUsed: -1 },
         } satisfies StrictUpdate<IUserDocument>,
         { session }
      );

      if (reverted.matchedCount === 0) {
         throw makeAppError(
            'CONCURRENCY_ERROR',
            409,
            'CONFLICT',
            `This email change could not be reverted automatically. Please contact an administrator.`
         );
      }

      await getSessionCollection().deleteMany(
         {
            userId: change.userId,
         } satisfies StrictMongoFilter<ISessionDocument>,
         { session }
      );

      /* The email binding already kills any reset link mailed to the attacker's address. Deleting the documents too also resets the forgot-password cooldown clock, so the owner's first request after a revert can never be swallowed by a request the attacker made seconds earlier. */
      await getPasswordResetCollection().deleteMany(
         {
            userId: change.userId,
         } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
         { session }
      );

      return { status: 'reverted', userId: change.userId };
   });
}

export async function cancelEmailChangeController(
   req: Request<CancelParams>,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = req.params;

      const tokenHash = generateStandardHash(token);

      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during email change reversion.`
         );
      }

      const session = authConnection.startSession();

      try {
         const result = await runCancelTransaction(session, tokenHash);

         if (result.status === 'invalid') {
            return void res
               .status(404)
               .json(
                  createErrorResponse(
                     'NOT_FOUND',
                     `This link is invalid, has expired, or was already used.`,
                     requestId
                  )
               );
         }

         if (result.status === 'cancelled') {
            securityLog.record({
               event: 'EMAIL_CHANGE_CANCELLED',
               actorId: null,
               targetUserId: result.userId,
               ...requestContext(req, res),
            });
            return void res.status(200).json({
               success: true,
               message: `Email change cancelled successfully.`,
            });
         }

         // 'reverted': every session was destroyed inside the transaction.
         clearAuthCookies(res);
         securityLog.record({
            event: 'EMAIL_CHANGE_REVERTED',
            actorId: null,
            targetUserId: result.userId,
            ...requestContext(req, res),
         });

         return void res.status(200).json({
            success: true,
            message: `Email change reverted successfully. Your previous address has been restored. Please log in again.`,
         });
      } finally {
         await session.endSession();
      }
   } catch (err) {
      next(err);
   }
}
