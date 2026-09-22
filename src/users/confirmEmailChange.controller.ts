import type { Request, Response, NextFunction } from 'express';
import { getUserCollection, IUserDocument } from '@models/User_v3.model.ts';
import {
   EmailChangeDocumentReadValidator,
   getEmailChangeCollection,
   IEmailChangeDocumentRead,
} from '@models/EmailChange_v3.model.ts';
import {
   getSessionCollection,
   ISessionDocument,
} from '@models/Session_v3.model.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import logger from '../logger.ts';
import { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';

type ConfirmParams = { token: string };

export async function confirmEmailChangeController(
   req: Request<ConfirmParams>,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = req.params;

      const tokenHash = generateStandardHash(token);
      const emailChangeCollection = getEmailChangeCollection();
      const userCollection = getUserCollection();

      // ── Look up the EmailChange record ─────────────────────────────────────────
      const emailChangeRaw = await emailChangeCollection.findOne({
         confirmTokenHash: tokenHash,
         expiresAt: { $gt: new Date() },
      } satisfies StrictMongoFilter<IEmailChangeDocumentRead>);

      if (!emailChangeRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `This link has expired or the email change has been cancelled.`,
                  requestId
               )
            );
      }

      const decodedEmailChange = Schema.decodeUnknownEither(
         EmailChangeDocumentReadValidator
      )(emailChangeRaw);

      if (Either.isLeft(decodedEmailChange)) {
         throw decodedEmailChange.left;
      }

      const validatedEmailChange = decodedEmailChange.right;

      // ── State guard ────────────────────────────────────────────────────────────
      if (validatedEmailChange.confirmedAt !== null) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `This email address has already been confirmed.`,
                  requestId
               )
            );
      }

      // ── Transaction: mark confirmed + update User ──────────────────────────────
      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during email confirmation.`
         );
      }

      const session = authConnection.startSession();
      try {
         await session.withTransaction(async () => {
            const emailChangeUpdateResult =
               await emailChangeCollection.updateOne(
                  {
                     _id: validatedEmailChange._id,
                     confirmedAt: null,
                  } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
                  {
                     $set: { confirmedAt: new Date() },
                  } satisfies StrictUpdate<IEmailChangeDocumentRead>,
                  { session }
               );

            if (emailChangeUpdateResult.modifiedCount === 0) {
               throw makeAppError(
                  'CONCURRENCY_ERROR',
                  409,
                  'CONFLICT',
                  `Email Change already confirmed.`
               );
            }

            /* The old email is pushed to the archive BEFORE being overwritten. archivedAt records the moment it stopped being the live address. */
            const userUpdateResult = await userCollection.updateOne(
               {
                  _id: validatedEmailChange.userId,
               } satisfies StrictMongoFilter<IUserDocument>,
               {
                  $set: { email: validatedEmailChange.newEmail },
                  $push: {
                     previousEmails: {
                        email: validatedEmailChange.oldEmail,
                        archivedAt: new Date(),
                     },
                  },
                  $inc: { emailChangesUsed: 1 },
               } satisfies StrictUpdate<IUserDocument>,
               { session }
            );

            if (userUpdateResult.matchedCount === 0) {
               throw makeAppError(
                  'CONCURRENCY_ERROR',
                  409,
                  'CONFLICT',
                  `User ${validatedEmailChange.userId} not found...`
               );
            }

            /* "Nuclear" logout inside the transaction. All sessions must be destroyed so the user re-authenticates against the new address. Placing this inside the transaction guarantees it is rolled back if either of the writes above fails. */
            await getSessionCollection().deleteMany(
               {
                  userId: validatedEmailChange.userId,
               } satisfies StrictMongoFilter<ISessionDocument>,
               { session }
            );

            logger.info(
               `New email ${validatedEmailChange.newEmail} has been confirmed.`,
               {
                  userId: validatedEmailChange.userId,
                  requestId,
               }
            );
         });
      } finally {
         await session.endSession();
      }

      clearAuthCookies(res);

      return void res.status(200).json({
         success: true,
         message: `Email address updated successfully. Please log in again.`,
      });
   } catch (err) {
      next(err);
   }
}
