import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import {
   getUserCollection,
   UserTotpManagementValidator,
   type IUserDocument,
   type IUserTotpManagement,
} from '@models/User_v3.model.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';
import {
   checkSecondFactor,
   sendSecondFactorFailure,
   toSecondFactorInput,
} from '@auth/secondFactor.ts';
import { revokeOtherSessions } from '@auth/revokeOtherSessions.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { DisableTotpBody } from '@auth/totp.schemas.ts';
import { USER_TOTP_MANAGEMENT_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';

export async function disableTotpController(
   _req: Request,
   res: ResponseWithValidatedBody<DisableTotpBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, sessionId } = res.locals.authenticatedUser;
      const { currentPassword, totpCode, recoveryCode } =
         res.locals.validatedBody;

      const userCollection = getUserCollection();
      const userRaw = await userCollection.findOne<IUserTotpManagement>(
         { _id: new ObjectId(sub) } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_TOTP_MANAGEMENT_PROJECTION,
         } satisfies StrictFindOneOptions<IUserTotpManagement>
      );

      if (userRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      const decodedUser = Schema.decodeUnknownEither(
         UserTotpManagementValidator
      )(userRaw);
      if (Either.isLeft(decodedUser)) {
         throw new Error(
            `Stored user failed validation while disabling TOTP.`,
            { cause: decodedUser.left }
         );
      }
      const user = decodedUser.right;

      // ── Factor 1: the password ─────────────────────────────────────────────────
      const isPasswordValid = await verifyPassword(
         user.passwordHash,
         currentPassword
      );
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

      // ── Factor 2: a current code or a recovery code ────────────────────────────
      const factor = toSecondFactorInput({ totpCode, recoveryCode });
      if (factor === null) {
         /* The schema guarantees exactly one; this branch exists so the type system doesn't have to trust that. */
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Provide exactly one of totpCode or recoveryCode.`,
                  requestId
               )
            );
      }

      const outcome = await checkSecondFactor(user, factor);
      if (outcome.status !== 'verified') {
         sendSecondFactorFailure(res, outcome);
         return;
      }

      // ── The downgrade: flag flip + session revocation, all or nothing ──────────
      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable while disabling TOTP.`
         );
      }

      const session = authConnection.startSession();
      try {
         await session.withTransaction(async () => {
            const disabled = await userCollection.updateOne(
               {
                  _id: user._id,
                  isTotpEnabled: true,
               } satisfies StrictMongoFilter<IUserDocument>,
               {
                  $set: {
                     isTotpEnabled: false,
                     totpSecret: null,
                     totpPendingSecret: null,
                     totpRecoveryCodes: [],
                     totpAttempts: 0,
                     totpAttemptsWindowStartedAt: null,
                  },
               } satisfies StrictUpdate<IUserDocument>,
               { session }
            );

            if (disabled.matchedCount === 0) {
               throw makeAppError(
                  'CONCURRENCY_ERROR',
                  409,
                  'CONFLICT',
                  `Two-factor authentication state changed. Please retry.`
               );
            }

            await revokeOtherSessions(user._id, new ObjectId(sessionId), {
               session,
            });
         });
      } finally {
         await session.endSession();
      }

      return void res.status(200).json({
         success: true,
         message: `Two-factor authentication has been disabled.`,
      });
   } catch (err) {
      next(err);
   }
}
