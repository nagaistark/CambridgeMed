import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import {
   getUserCollection,
   UserLoginValidator,
   type IUserDocument,
   type IUserLogin,
} from '@models/User_v3.model.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { hashPassword, verifyPassword } from '@utils/hashAndVerify.ts';
import {
   signTotpChallengeToken,
   setTotpChallengeCookie,
} from '@utils/tokenUtils.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import type { LoginBody } from '@auth/login.schema.ts';
import type { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';
import { issueSession } from '@utils/issueSession.ts';
import { generateRandomToken } from '@ssot/node_crypto_constants.ts';
import { USER_LOGIN_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';

/* A real hash, made once at startup with the CURRENT ARGON2_CONFIG, of a password nobody knows. When no user matches, we still run a full verification against it so "no such user" costs the same as "wrong password". Because it is generated rather than pasted, it cannot drift from the config. */
const TIMING_DUMMY_HASH: string = await hashPassword(generateRandomToken());

export async function loginController(
   req: Request,
   res: ResponseWithValidatedBody<LoginBody>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { email, password } = res.locals.validatedBody;

      const userRaw = await getUserCollection().findOne<IUserLogin>(
         { email } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_LOGIN_PROJECTION,
         } satisfies StrictFindOneOptions<IUserLogin>
      );

      let user: IUserLogin | null = null;
      if (userRaw !== null) {
         const decodedUser =
            Schema.decodeUnknownEither(UserLoginValidator)(userRaw);
         if (Either.isLeft(decodedUser)) {
            throw new Error(`Stored user failed validation during login.`, {
               cause: decodedUser.left,
            });
         }
         user = decodedUser.right;
      }

      const isPasswordValid = await verifyPassword(
         user?.passwordHash ?? TIMING_DUMMY_HASH,
         password
      );

      // Deliberately vague: same message for "no such user" and "wrong password".
      if (user === null || !isPasswordValid) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Invalid email or password.`,
                  requestId
               )
            );
      }

      /* AFTER the credential check on purpose: revealing "deactivated" is acceptable only to someone who has just proven the password. */
      if (!user.isActive) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `This account has been deactivated. Please contact an administrator.`,
                  requestId
               )
            );
      }

      if (user.passwordResetRequired) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `For your security, you must reset your password before logging in. Use "Forgot password" to receive a reset link.`,
                  requestId
               )
            );
      }

      // ── TOTP gate (logic unchanged; TOTP is tabled) ────────────────────────────
      if (user.isTotpEnabled) {
         const challengeToken = await signTotpChallengeToken(
            user._id.toString()
         );
         setTotpChallengeCookie(res, challengeToken);

         return void res.status(202).json({
            success: true,
            requiresTotp: true,
            message: `Two-factor authentication required.`,
         });
      }

      await issueSession(user, req, res);

      return void res
         .status(200)
         .json(buildAuthResponse('Login successful', user));
   } catch (err) {
      next(err);
   }
}
