import type { Request, NextFunction } from 'express';
import type {
   TotpChallengeResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { RecoveryCodeBody } from '@auth/totp.schemas.ts';
import { completeTotpLogin } from '@auth/completeTotpLogin.ts';

export async function recoverTotpController(
   req: Request,
   res: ResponseWithValidatedBody<RecoveryCodeBody> & TotpChallengeResponse,
   next: NextFunction
): Promise<void> {
   try {
      await completeTotpLogin(req, res, {
         kind: 'recovery',
         code: res.locals.validatedBody.code,
      });
   } catch (err) {
      next(err);
   }
}
