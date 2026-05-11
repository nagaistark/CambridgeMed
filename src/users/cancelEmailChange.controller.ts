import type { Request, Response, NextFunction } from 'express';
import { getUserModel } from '@models/User.model.ts';
import { getEmailChangeModel } from '@models/EmailChange.model.ts';
import { getSessionModel } from '@models/Session.model.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { DatabaseManager } from 'dbConnect.ts';
import {
   generateStandardHash,
   HEX96_REGEX,
} from '@ssot/node_crypto_constants.ts';
import logger from 'logger.ts';

type CancelParams = { token: string };

export async function cancelEmailChangeController(
   req: Request<CancelParams>,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = req.params;

      // ── Token format check ─────────────────────────────────────────────────────
      if (!HEX96_REGEX.test(token)) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `This link is invalid.`,
                  requestId
               )
            );
      }

      const tokenHash = generateStandardHash(token);
      const EmailChange = getEmailChangeModel();
      const User = getUserModel();

      // ── Look up the EmailChange record ─────────────────────────────────────────
      const emailChange = await EmailChange.findOne({
         cancelTokenHash: tokenHash,
         expiresAt: { $gt: new Date() },
      }).lean();

      if (!emailChange) {
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

      // ── Simple cancel / deletion and reversion ─────────────────────────────────

      /*  Simple cancel/deletion (confirmedAt === null): The change was never applied. We just delete the record so the confirmation link becomes permanently inert. No User document mutation is needed. No session kill is needed.

      Reversion (confirmedAt !== null): The change already went through. User.email is currently newEmail. We must revert the User document, archive newEmail in previousEmails, increment the counter, and kill all sessions. */

      const authConnection = DatabaseManager.getInstance().auth.connection;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during email change reversion.`
         );
      }

      let isReversion: boolean = false;

      const session = await authConnection.startSession();
      try {
         await session.withTransaction(async () => {
            isReversion = emailChange.confirmedAt !== null;

            if (isReversion) {
               await User.updateOne(
                  { _id: emailChange.userId },
                  {
                     $set: { email: emailChange.oldEmail },
                     $push: {
                        previousEmails: {
                           email: emailChange.newEmail,
                           archivedAt: new Date(),
                        },
                     },
                     $inc: { emailChangesUsed: 1 },
                  },
                  { session, runValidators: true }
               );

               /* Nuclear logout inside the transaction. */
               await getSessionModel().deleteMany(
                  { userId: emailChange.userId },
                  { session }
               );
            }

            const deleteResult = await getEmailChangeModel().deleteOne(
               { _id: emailChange._id },
               { session }
            );

            // Fail-fast: check if the document was actually there to be deleted
            if (deleteResult.deletedCount === 0) {
               // This triggers the rollback.
               throw new Error(
                  `CONCURRENCY_ERROR: Document already processed.`
               );
            }

            // If we make it here, the transaction is committed.
            logger.info(
               `Email change ${isReversion ? 'reverted' : 'cancelled'}`,
               {
                  userId: emailChange.userId,
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
