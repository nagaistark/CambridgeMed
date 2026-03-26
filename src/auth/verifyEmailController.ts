import { Request, Response, NextFunction } from 'express';
import { jwtVerify } from 'jose';
import { getPublicKey } from '@utils/jwtUtils.ts';
import { getUserModel } from '@models/User.model.ts';
import { createErrorResponse } from '@/errorHandlers.ts';
import { EMAIL_VERIFICATION_AUDIENCE } from '@/_SSOT/email_verification_constants.ts';

export async function verifyEmailController(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals['requestId'];
      const { token } = req.query;

      // ── 1. Token presence check ─────────────────────────────────────────
      if (typeof token !== 'string' || token.trim() === '') {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  'Verification token is missing.',
                  undefined,
                  requestId
               )
            );
      }

      // ── 2. Verify the JWT ───────────────────────────────────────────────
      /* jwtVerify does three things in one call:
         a) Validates the RS256 signature against our public key.
         b) Checks that the token hasn't expired (exp claim).
         c) Checks that `aud` matches EMAIL_VERIFICATION_AUDIENCE.
      
      If any of these fail, jose throws a JOSEError subclass, which handleJwtError catches and converts to an appropriate 401 response. Nothing leaks about "why" the token was rejected — just "invalid." */
      const publicKey = await getPublicKey();

      // jwtVerify throws JWTExpired if expired, JWSInvalid if tampered. Both are caught by handleJwtError already registered in our pipeline.
      const { payload } = await jwtVerify(token, publicKey, {
         algorithms: ['RS256'],
         audience: EMAIL_VERIFICATION_AUDIENCE,
      });

      // ── 3. Extract subject ──────────────────────────────────────────────
      /* `sub` was set to user._id.toString() in registerController. It should always be present given our own token structure, but we guard it defensively. Never assume payload shape, even for our own tokens. */
      const userId = payload.sub;
      if (!userId) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  'Invalid or malformed token.',
                  undefined,
                  requestId
               )
            );
      }

      // ── 4. Mark user as verified ────────────────────────────────────────
      /* `findByIdAndUpdate` is atomic — no risk of a read-then-write race. We don't return the updated document (`new: true` omitted) because we only need to know whether the document existed at all. */
      const user = await getUserModel().findByIdAndUpdate(userId, {
         isVerified: true,
      });

      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  'Account not found.',
                  undefined,
                  requestId
               )
            );
      }

      // ── 5. Respond ──────────────────────────────────────────────────────
      return void res.status(200).json({
         success: true,
         message: `Email verified successfully. You may now log in.`,
      });
   } catch (err) {
      next(err);
   }
}
