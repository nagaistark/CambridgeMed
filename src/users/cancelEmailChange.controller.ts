import type { Request, Response, NextFunction } from 'express';
import { getUserCollection, IUserDocument } from '@models/User_v3.model.ts';
import {
   EmailChangeDocumentValidator,
   getEmailChangeCollection,
   IEmailChangeDocument,
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

type CancelParams = { token: string };

export async function cancelEmailChangeController(
   req: Request<CancelParams>,
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
         cancelTokenHash: tokenHash,
         expiresAt: { $gt: new Date() },
      } satisfies StrictMongoFilter<IEmailChangeDocument>);

      if (!emailChangeRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `This link is invalid or has already been used.`,
                  requestId
               )
            );
      }

      const decodedEmailChange = Schema.decodeUnknownEither(
         EmailChangeDocumentValidator
      )(emailChangeRaw);

      if (Either.isLeft(decodedEmailChange)) {
         throw decodedEmailChange.left;
      }

      const validatedEmailChange = decodedEmailChange.right;

      // ── Simple cancel / deletion and reversion ─────────────────────────────────

      /*  Simple cancel/deletion (confirmedAt === null): The change was never applied. We just delete the record so the confirmation link becomes permanently inert. No User document mutation is needed. No session kill is needed.

      Reversion (confirmedAt !== null): The change already went through. User.email is currently newEmail. We must revert the User document, archive newEmail in previousEmails, increment the counter, and kill all sessions. */

      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during email change reversion.`
         );
      }

      let isReversion: boolean = false;

      const session = authConnection.startSession();
      try {
         await session.withTransaction(async () => {
            isReversion = validatedEmailChange.confirmedAt !== null;

            if (isReversion) {
               const userUpdateResult = await userCollection.updateOne(
                  {
                     _id: validatedEmailChange.userId,
                  } satisfies StrictMongoFilter<IUserDocument>,
                  {
                     $set: { email: validatedEmailChange.oldEmail },
                     $push: {
                        previousEmails: {
                           email: validatedEmailChange.newEmail,
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

               /* Nuclear logout inside the transaction. */
               await getSessionCollection().deleteMany(
                  {
                     userId: validatedEmailChange.userId,
                  } satisfies StrictMongoFilter<ISessionDocument>,
                  { session }
               );
            }

            const deleteResult = await getEmailChangeCollection().deleteOne(
               { _id: validatedEmailChange._id },
               { session }
            );

            // Fail-fast: check if the document was actually there to be deleted
            if (deleteResult.deletedCount === 0) {
               // This triggers the rollback.
               throw makeAppError(
                  'CONCURRENCY_ERROR',
                  409,
                  'CONFLICT',
                  `Document already processed.`
               );
            }

            // If we make it here, the transaction is committed.
            logger.info(
               `Email change ${isReversion ? 'reverted' : 'cancelled'}`,
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
         message: isReversion
            ? `Email change reverted successfully. Your previous address has been restored. Please log in again.`
            : `Email change cancelled successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
