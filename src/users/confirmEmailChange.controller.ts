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
      const EmailChange = getEmailChangeModel();
      const User = getUserModel();

      // ── Look up the EmailChange record ─────────────────────────────────────────
      const emailChange = await EmailChange.findOne({
         confirmTokenHash: tokenHash,
         expiresAt: { $gt: new Date() },
      }).lean();

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
      const authConnection = DatabaseManager.getInstance().auth.connection;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during email confirmation.`
         );
      }

      const session = await authConnection.startSession();
      try {
         await session.withTransaction(async () => {
            const updateResult = await EmailChange.updateOne(
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
            await User.updateOne(
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
               { session, runValidators: true }
            );

            /* "Nuclear" logout inside the transaction. All sessions must be destroyed so the user re-authenticates against the new address. Placing this inside the transaction guarantees it is rolled back if either of the writes above fails. */
            await getSessionModel().deleteMany(
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
