import type { Request, NextFunction } from 'express';
import { verify } from 'otplib';
import { getUserModel } from '@models/User.model.ts';
import {
   decryptTotpSecret,
   generateRecoveryCodes,
   hashRecoveryCode,
} from '@utils/totpCrypto.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { TotpCodeBody } from '@auth/totp.schemas.ts';

export async function confirmTotpEnrollmentController(
   _req: Request,
   res: ResponseWithValidatedBody<TotpCodeBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { code } = res.locals.validatedBody;

      const User = getUserModel();
      const user = await User.findById(sub).lean();

      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      if (!user.totpSecret) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `No pending TOTP enrollment found. Please start the enrollment process first.`,
                  requestId
               )
            );
      }

      if (user.isTotpEnabled) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `Two-factor authentication is already enabled.`,
                  requestId
               )
            );
      }

      // ── Verify the submitted code ──────────────────────────────────────────────
      const rawSecret = decryptTotpSecret(user.totpSecret);
      const result = await verify({
         token: code,
         secret: rawSecret,
      });

      if (!result.valid) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Invalid code. Please check your authenticator app and try again.`,
                  requestId
               )
            );
      }

      // ── Generate and persist recovery codes ────────────────────────────────────
      /* Plaintext codes are generated, hashed for storage, then returned to the user exactly once. The plaintext is never persisted anywhere — after this response is sent, it is gone forever. */
      const plainTextCodes = generateRecoveryCodes();
      const hashedCodes = plainTextCodes.map(hashRecoveryCode);

      await User.updateOne(
         { _id: user._id },
         {
            $set: {
               isTotpEnabled: true,
               totpRecoveryCodes: hashedCodes,
            },
         },
         { runValidators: true }
      );

      return void res.status(200).json({
         success: true,
         message: `Two-factor authentication enabled successfully.`,
         recoveryCodes: plainTextCodes,
         recoveryCodesWarning: `Save these codes somewhere safe. Each can be used once if you lose access to your authenticator app. They will not be shown again.`,
      });
   } catch (err) {
      next(err);
   }
}
