import type { Request, Response, NextFunction } from 'express';
import { getUserCollection } from '@models/User_v3.model.ts';
import { getEmailChangeCollection } from '@models/EmailChange_v3.model.ts';
import { getSessionCollection } from '@models/Session_v3.model.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { DatabaseManager } from 'mongoDBConnect.ts';
import {
   generateStandardHash,
   HEX96_REGEX,
} from '@ssot/node_crypto_constants.ts';
import logger from 'logger.ts';

type ConfirmParams = { token: string };

export async function confirmEmailChangeController(
   req: Request<ConfirmParams>,
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
      const emailChangeCollection = getEmailChangeCollection();
      const userCollection = getUserCollection();

      // ── Look up the EmailChange record ─────────────────────────────────────────
      const emailChange = await emailChangeCollection.findOne({
         confirmTokenHash: tokenHash,
         expiresAt: { $gt: new Date() },
      });

      if (!emailChange) {
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

      // ── State guard ────────────────────────────────────────────────────────────
      if (emailChange.confirmedAt !== null) {
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
            const updateResult = await emailChangeCollection.updateOne(
               { _id: emailChange._id, confirmedAt: null },
               { $set: { confirmedAt: new Date() } },
               { session }
            );

            if (updateResult.modifiedCount === 0) {
               throw new Error(
                  'CONCURRENCY_ERROR: Email change already confirmed.'
               );
            }

            /* The old email is pushed to the archive BEFORE being overwritten. archivedAt records the moment it stopped being the live address. */
            await userCollection.updateOne(
               { _id: emailChange.userId },
               {
                  $set: { email: emailChange.newEmail },
                  $push: {
                     previousEmails: {
                        email: emailChange.oldEmail,
                        archivedAt: new Date(),
                     },
                  },
                  $inc: { emailChangesUsed: 1 },
               },
               { session }
            );

            /* "Nuclear" logout inside the transaction. All sessions must be destroyed so the user re-authenticates against the new address. Placing this inside the transaction guarantees it is rolled back if either of the writes above fails. */
            await getSessionCollection().deleteMany(
               { userId: emailChange.userId },
               { session }
            );

            logger.info(
               `New email ${emailChange.newEmail} has been confirmed.`,
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
         message: `Email address updated successfully. Please log in again.`,
      });
   } catch (err) {
      next(err);
   }
}
