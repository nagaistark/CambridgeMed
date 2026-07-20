import type { Request, NextFunction } from 'express';
import { getUserCollection } from '@models/User_v3.model.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { DisableTotpBody } from '@auth/totp.schemas.ts';
import { ObjectId } from 'mongodb';

export async function disableTotpController(
   _req: Request,
   res: ResponseWithValidatedBody<DisableTotpBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { password } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const user = await userCollection.findOne({ _id: new ObjectId(sub) });

      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      if (!user.isTotpEnabled) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Two-factor authentication is not currently enabled.`,
                  requestId
               )
            );
      }

      // ── Require password confirmation ──────────────────────────────────────────
      /* This is a deliberately high bar. Disabling 2FA is a security downgrade — we need to confirm the request is intentional by the account owner, not someone who walked up to an unlocked screen. */
      const isPasswordValid = await verifyPassword(user.passwordHash, password);

      if (!isPasswordValid) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Incorrect password.`,
                  requestId
               )
            );
      }

      // ── Clear all TOTP state in one atomic update ──────────────────────────────
      await userCollection.updateOne(
         { _id: user._id },
         {
            $set: {
               isTotpEnabled: false,
               totpSecret: null,
               totpRecoveryCodes: [],
            },
         }
      );

      return void res.status(200).json({
         success: true,
         message: `Two-factor authentication has been disabled.`,
      });
   } catch (err) {
      next(err);
   }
}
