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
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import logger from '../logger.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import type { ClientSession, ObjectId } from 'mongodb';

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
            expiresAt: { $gt: now },
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
            $set: { email: change.oldEmail, updatedAt: now },
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
            return void res.status(200).json({
               success: true,
               message: `Email change cancelled successfully.`,
            });
         }

         // 'reverted': every session was destroyed inside the transaction.
         clearAuthCookies(res);
         logger.warn(`Confirmed email change was reverted.`, {
            userId: result.userId,
            requestId,
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
