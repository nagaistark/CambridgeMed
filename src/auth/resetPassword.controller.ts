import type { Request, NextFunction } from 'express';
import { getUserCollection, IUserDocument } from '@models/User_v3.model.ts';
import {
   getPasswordResetCollection,
   IPasswordResetDocument,
} from '@models/PasswordReset_v3.model.ts';
import {
   getSessionCollection,
   ISessionDocument,
} from '@models/Session_v3.model.ts';
import { hashPassword } from '@utils/hashAndVerify.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';
import {
   generateStandardHash,
   HEX96_REGEX,
} from '@ssot/node_crypto_constants.ts';
import { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';
import type { ResetPasswordBody } from '@auth/resetPassword.schema.ts';
import { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';

type ResetPasswordParams = { token: string };

export async function resetPasswordController(
   req: Request<ResetPasswordParams>,
   res: ResponseWithValidatedBody<ResetPasswordBody>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = req.params;
      const { newPassword } = res.locals.validatedBody;

      // ── Token format check ─────────────────────────────────────────────────────
      /* A structurally invalid token cannot possibly match any stored hash. We return 404 rather than 400 here — consistent with the email change controllers — because we don't want to give a probing attacker any signal about what a "valid" token looks like. */
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

      const passwordReset = await getPasswordResetCollection().findOne({
         tokenHash,
         expiresAt: { $gt: new Date() },
      } satisfies StrictMongoFilter<IPasswordResetDocument>);

      if (!passwordReset) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `This link is invalid or has expired.`,
                  requestId
               )
            );
      }

      // ── Hash the new password BEFORE the transaction ───────────────────────────
      const newPasswordHash = await hashPassword(newPassword);

      // ── Transactional claim + update ───────────────────────────────────────────
      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during password reset.`
         );
      }

      const session = authConnection.startSession();
      try {
         await session.withTransaction(async () => {
            /* deleteOne is the serialisation point. By including { _id } in the filter, we atomically claim this specific document. If a concurrent request already claimed it (deletedCount === 0), we throw and the transaction rolls back, leaving the User document untouched. */
            const deleteResult = await getPasswordResetCollection().deleteOne(
               {
                  _id: passwordReset._id,
               } satisfies StrictMongoFilter<IPasswordResetDocument>,
               { session }
            );

            if (deleteResult.deletedCount === 0) {
               throw new Error(
                  `CONCURRENCY_ERROR: Password reset token already used.`
               );
            }

            await getUserCollection().updateOne(
               {
                  _id: passwordReset.userId,
               } satisfies StrictMongoFilter<IUserDocument>,
               {
                  $set: { passwordHash: newPasswordHash },
               } satisfies StrictUpdate<IUserDocument>
            );

            /* Kill all active sessions. The user just proved control of their email address, which is the recovery credential — all other devices should be forced to -authenticate against the new password. */
            await getSessionCollection().deleteMany(
               {
                  userId: passwordReset.userId,
               } satisfies StrictMongoFilter<ISessionDocument>,
               { session }
            );
         });
      } finally {
         await session.endSession();
      }

      clearAuthCookies(res);

      return void res.status(200).json({
         success: true,
         message: `Password reset successfully. Please log in with your new password.`,
      });
   } catch (err) {
      next(err);
   }
}
