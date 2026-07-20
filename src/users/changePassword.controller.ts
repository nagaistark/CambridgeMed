import type { Request, NextFunction } from 'express';

import { getUserCollection } from '@models/User_v3.model.ts';
import { getSessionCollection } from '@models/Session_v3.model.ts';
import { hashPassword, verifyPassword } from '@utils/hashAndVerify.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { DatabaseManager } from 'mongoDBConnect.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { ChangePasswordBody } from '@users/User_v3.schemas.ts';
import { ObjectId } from 'mongodb';

export async function changePasswordController(
   _req: Request,
   res: ResponseWithValidatedBody<ChangePasswordBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { currentPassword, newPassword } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const user = await userCollection.findOne({ _id: new ObjectId(sub) });

      /* Should never be null (the user just passed authenticate), but we guard defensively rather than using a non-null assertion. */
      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      // ── Step 1: verify the current password ────────────────────────────────────
      const isCurrentValid = await verifyPassword(
         user.passwordHash,
         currentPassword
      );

      if (!isCurrentValid) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Current password is incorrect.`,
                  requestId
               )
            );
      }

      // ── Step 2: hash the new password before opening the transaction ───────────
      /* Hashing optimistically up front. If anything downstream fails, the hash is discarded. The same-password case is already caught by the cross-field `check` in ChangePasswordVSchema. No duplicate `verifyPassword` call is needed here. */
      const newPasswordHash = await hashPassword(newPassword);

      // ── Step 3: atomic update + session destruction ────────────────────────────
      /* Transaction because the two writes must succeed OR fail as a unit. */
      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during password change.`
         );
      }

      const session = await authConnection.startSession();
      try {
         await session.withTransaction(async () => {
            await userCollection.updateOne(
               { _id: new ObjectId(sub) },
               { $set: { passwordHash: newPasswordHash } }
            );

            await getSessionCollection().deleteMany(
               { userId: new ObjectId(sub) },
               { session }
            );
         });
      } finally {
         await session.endSession();
      }

      clearAuthCookies(res);

      return void res.status(200).json({
         success: true,
         message: `Password changed successfully. You have been logged out of all devices.`,
      });
   } catch (err) {
      next(err);
   }
}
