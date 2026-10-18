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
import logger from '../logger.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import type { ClientSession, ObjectId } from 'mongodb';
import { EMAIL_CHANGE_CAP } from '@ssot/user_change_constants.ts';

type ConfirmParams = { token: string };
type ConfirmOutcome =
   { status: 'invalid' } | { status: 'confirmed'; userId: ObjectId };

async function runConfirmTransaction(
   session: ClientSession,
   tokenHash: string
): Promise<ConfirmOutcome> {
   return session.withTransaction(async (): Promise<ConfirmOutcome> => {
      const now = new Date();

      const claimedRaw = await getEmailChangeCollection().findOneAndUpdate(
         {
            confirmTokenHash: tokenHash,
            confirmExpiresAt: { $gt: now },
            confirmedAt: null,
         } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
         {
            $set: { confirmedAt: now, updatedAt: now },
         } satisfies StrictUpdate<IEmailChangeDocumentRead>,
         { returnDocument: 'after', session }
      );

      if (claimedRaw === null) return { status: 'invalid' };

      const decoded = Schema.decodeUnknownEither(
         EmailChangeDocumentReadValidator
      )(claimedRaw);

      if (Either.isLeft(decoded)) throw decoded.left;

      const change = decoded.right;

      const applied = await getUserCollection().updateOne(
         {
            _id: change.userId,
            email: change.oldEmail,
            isActive: true,
            emailChangesUsed: { $lt: EMAIL_CHANGE_CAP },
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { email: change.newEmail, updatedAt: now },
            $push: {
               previousEmails: { email: change.oldEmail, archivedAt: now },
            },
            $inc: { emailChangesUsed: 1 },
         } satisfies StrictUpdate<IUserDocument>,
         { session }
      );

      if (applied.matchedCount === 0) {
         throw makeAppError(
            'CONCURRENCY_ERROR',
            409,
            'CONFLICT',
            `This email change can no longer be applied. Please start over.`
         );
      }

      /* "Nuclear" logout inside the transaction. All sessions must be destroyed so the user re-authenticates against the new address. Placing this inside the transaction guarantees it is rolled back if either of the writes above fails. */
      await getSessionCollection().deleteMany(
         {
            userId: change.userId,
         } satisfies StrictMongoFilter<ISessionDocument>,
         { session }
      );

      await getPasswordResetCollection().deleteMany(
         {
            userId: change.userId,
         } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
         { session }
      );

      return { status: 'confirmed', userId: change.userId };
   });
}

export async function confirmEmailChangeController(
   req: Request<ConfirmParams>,
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
            `Auth database connection unavailable during email confirmation.`
         );
      }

      const session = authConnection.startSession();

      try {
         const result = await runConfirmTransaction(session, tokenHash);

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

         clearAuthCookies(res);

         logger.info(`Email change confirmed.`, {
            userId: result.userId,
            requestId,
         });

         return void res.status(200).json({
            success: true,
            message: `Email address updated successfully. Please log in again.`,
         });
      } finally {
         await session.endSession();
      }
   } catch (err) {
      next(err);
   }
}
