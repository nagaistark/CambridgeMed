import type { Request, NextFunction } from 'express';
import type {
   TotpChallengeResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { TotpCodeBody } from '@auth/totp.schemas.ts';
import { completeTotpLogin } from '@auth/completeTotpLogin.ts';

export async function verifyTotpController(
   req: Request,
   res: ResponseWithValidatedBody<TotpCodeBody> & TotpChallengeResponse,
   next: NextFunction
): Promise<void> {
   try {
      await completeTotpLogin(req, res, {
         kind: 'totp',
         code: res.locals.validatedBody.code,
      });
   } catch (err) {
      next(err);
   }
}
