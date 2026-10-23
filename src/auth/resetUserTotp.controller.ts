import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import {
   getUserCollection,
   UserPasswordResetTargetValidator,
   UserTotpManagementValidator,
   type IUserDocument,
   type IUserPasswordResetTarget,
   type IUserTotpManagement,
} from '@models/User_v3.model.ts';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import {
   getPasswordResetCollection,
   type IPasswordResetDocumentRead,
} from '@models/PasswordReset_v3.model.ts';
import {
   getEmailChangeCollection,
   type IEmailChangeDocumentRead,
} from '@models/EmailChange_v3.model.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';
import {
   clearSecondFactorAttempts,
   consumeSecondFactor,
   recordFactorUsage,
   sendSecondFactorFailure,
   toSecondFactorInput,
   verifySecondFactor,
   type FactorClaim,
   type SecondFactorContext,
} from '@auth/secondFactor.ts';
import { sendTotpResetByAdminEmail } from '@users/totpResetByAdmin.email.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { sanitizeError } from '../mongoDBConnect.ts';
import logger from '../logger.ts';
import { withAuthTransaction } from '@utils/withAuthTransaction.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import type { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import type { AdminResetTotpBody } from '@auth/totp.schemas.ts';
import { allowedRoles } from '@ssot/user_roles_constants.ts';
import {
   USER_PASSWORD_RESET_TARGET_PROJECTION,
   USER_TOTP_MANAGEMENT_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneAndUpdateOptions,
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';

/* A failed notification must never undo a completed reset, but must not vanish silently. Cannot reject. */
async function notifyOwner(target: IUserPasswordResetTarget): Promise<void> {
   try {
      await sendTotpResetByAdminEmail({
         firstName: target.firstName,
         email: target.email,
      });
   } catch (err) {
      logger.error(
         `2FA-reset notification failed: ${sanitizeError(err).message}`
      );
   }
}

/* POST /api/users/:id/totp/reset   (MANAGE_USERS, i.e. superadmin)
   POST, not DELETE: it carries a body (the admin's re-authentication), and bodies on DELETE are undefined behaviour in HTTP.

   Threat model: the realistic attack is not a hacker, it is a friendly voice on the phone claiming to have lost their phone. So the reset is built to make that attack insufficient on its own:
   1. The ADMIN re-authenticates (password + their own second factor if enabled), so a hijacked admin session cannot strip protections from everyone.
   2. The target gets `passwordResetRequired: true`. Logging in again requires "Forgot password", which proves control of the mailbox on file. A caller who talked their way past the admin still needs the victim's inbox.
   3. Every live credential the old state authorised dies in the same transaction: sessions, pending password-reset links, unconfirmed email changes.
   4. The owner is emailed at the address on file, and a security event records who did it. */
export async function resetUserTotpController(
   req: Request,
   res: ResponseWithValidatedBody<AdminResetTotpBody> &
      ResponseWithValidatedParams<IMongoIdParam> &
      AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;
      const { currentPassword, totpCode, recoveryCode } =
         res.locals.validatedBody;

      const userCollection = getUserCollection();

      // ── The admin proves who they are, right now ───────────────────────────────
      const adminRaw = await userCollection.findOne<IUserTotpManagement>(
         { _id: new ObjectId(sub) } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_TOTP_MANAGEMENT_PROJECTION,
         } satisfies StrictFindOneOptions<IUserTotpManagement>
      );
      if (adminRaw === null) {
         throw new Error(
            `Authenticated user not found in database during admin TOTP reset. userId=${sub}`
         );
      }

      const decodedAdmin = Schema.decodeUnknownEither(
         UserTotpManagementValidator
      )(adminRaw);
      if (Either.isLeft(decodedAdmin)) {
         throw new Error(
            `Stored admin failed validation during admin TOTP reset.`,
            { cause: decodedAdmin.left }
         );
      }
      const admin = decodedAdmin.right;

      const isPasswordValid = await verifyPassword(
         admin.passwordHash,
         currentPassword
      );
      if (!isPasswordValid) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'INVALID_CREDENTIALS',
                  `Incorrect password.`,
                  requestId
               )
            );
      }

      const context: SecondFactorContext = {
         purpose: 'admin-reset',
         actorId: admin._id,
         ...requestContext(req, res),
      };

      let adminClaim: FactorClaim | null = null;
      if (admin.isTotpEnabled) {
         const factor = toSecondFactorInput({ totpCode, recoveryCode });
         if (factor === null) {
            return void res
               .status(403)
               .json(
                  createErrorResponse(
                     'FORBIDDEN',
                     `A two-factor authentication code is required for this action.`,
                     requestId,
                     { requiresTotp: true }
                  )
               );
         }

         const verification = await verifySecondFactor(admin, factor, context);
         if (verification.status !== 'verified') {
            sendSecondFactorFailure(res, verification, 403);
            return;
         }
         adminClaim = verification.claim;
      }

      // ── One transaction: spend the admin's code, strip the target, sweep ───────
      const { target, sessionsRevoked } = await withAuthTransaction(
         async session => {
            if (adminClaim !== null) {
               const consumption = await consumeSecondFactor(adminClaim, {
                  session,
               });
               if (consumption.status === 'rejected') {
                  throw makeAppError(
                     'FACTOR_REJECTED',
                     403,
                     'INVALID_CREDENTIALS',
                     `Invalid code.`
                  );
               }
            }

            /* The filter IS the decision: "this user exists AND holds an assignable role (superadmin stays untouchable) AND currently has 2FA enabled". */
            const targetRaw = await userCollection.findOneAndUpdate(
               {
                  _id: id,
                  role: { $in: allowedRoles },
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
                     passwordResetRequired: true,
                     updatedAt: new Date(),
                  },
               } satisfies StrictUpdate<IUserDocument>,
               {
                  projection: USER_PASSWORD_RESET_TARGET_PROJECTION,
                  returnDocument: 'after',
                  session,
               } satisfies StrictFindOneAndUpdateOptions<IUserPasswordResetTarget>
            );

            if (targetRaw === null) {
               throw makeAppError(
                  'TARGET_NOT_RESETTABLE',
                  404,
                  'NOT_FOUND',
                  `User not found, or two-factor authentication is not enabled for this account.`
               );
            }

            const decodedTarget = Schema.decodeUnknownEither(
               UserPasswordResetTargetValidator
            )(targetRaw);
            if (Either.isLeft(decodedTarget)) {
               throw new Error(
                  `Stored target user failed validation during admin TOTP reset.`,
                  { cause: decodedTarget.left }
               );
            }
            const resolvedTarget = decodedTarget.right;

            const sessions = await getSessionCollection().deleteMany(
               {
                  userId: resolvedTarget._id,
               } satisfies StrictMongoFilter<ISessionDocument>,
               { session }
            );

            /* A reset link issued while 2FA was on would otherwise be redeemable without the step-up the moment 2FA is gone. */
            await getPasswordResetCollection().deleteMany(
               {
                  userId: resolvedTarget._id,
               } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
               { session }
            );

            /* Unconfirmed only: a confirmed change's cancel link is the owner's recovery handle (same rule as everywhere else). */
            await getEmailChangeCollection().deleteMany(
               {
                  userId: resolvedTarget._id,
                  confirmedAt: null,
               } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
               { session }
            );

            return {
               target: resolvedTarget,
               sessionsRevoked: sessions.deletedCount,
            };
         }
      );

      // ── After the commit ───────────────────────────────────────────────────────
      if (adminClaim !== null) {
         await clearSecondFactorAttempts(admin._id);
         recordFactorUsage(adminClaim, context);
      }

      securityLog.record({
         event: 'TOTP_RESET_BY_ADMIN',
         actorId: admin._id,
         targetUserId: target._id,
         ...requestContext(req, res),
      });
      logger.warn(`Two-factor authentication reset by administrator.`, {
         requestId,
         actorId: sub,
         targetId: target._id.toHexString(),
         sessionsRevoked,
      });

      res.status(200).json({
         success: true,
         message: `Two-factor authentication reset. The user must set a new password before logging in again.`,
      });

      /* Response first; the mail round trip is not the admin's problem. */
      await notifyOwner(target);
   } catch (err) {
      next(err);
   }
}
