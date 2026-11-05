import type { Request, NextFunction } from 'express';
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
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import { upgradePasswordHashIfStale } from '@auth/upgradePasswordHash.ts';

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

      let validatedUser: IUserLogin | null = null;
      if (userRaw !== null) {
         validatedUser = decodeStored(
            UserLoginValidator,
            userRaw,
            'login user'
         );
      }

      const isPasswordValid = await verifyPassword(
         validatedUser?.passwordHash ?? TIMING_DUMMY_HASH,
         password
      );

      // Deliberately vague: same message for "no such user" and "wrong password".
      if (validatedUser === null || !isPasswordValid) {
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
      if (!validatedUser.isActive) {
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

      if (validatedUser.passwordResetRequired) {
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

      /* The password is proven correct here, for BOTH the password-only path and the TOTP path (the 202 branch below never sees the plaintext again). Only a valid password can trigger the extra Argon2 run, so this adds no amplification for attackers. */
      await upgradePasswordHashIfStale(validatedUser, password, requestId);

      // ── TOTP gate (logic unchanged; TOTP is tabled) ────────────────────────────
      if (validatedUser.isTotpEnabled) {
         const challengeToken = await signTotpChallengeToken(
            validatedUser._id.toString()
         );
         setTotpChallengeCookie(res, challengeToken);

         return void res.status(202).json({
            success: true,
            requiresTotp: true,
            message: `Two-factor authentication required.`,
         });
      }

      /* Read-only and fallible, so it goes BEFORE issueSession commits a session and sets cookies. Placed after every credential check: unknown emails and the 202 challenge path never reach it. */
      const emailChange = await loadEmailChangeStatus(
         validatedUser._id,
         new Date()
      );

      await issueSession(validatedUser, req, res);

      return void res
         .status(200)
         .json(
            buildAuthResponse('Login successful', validatedUser, emailChange)
         );
   } catch (err) {
      next(err);
   }
}
