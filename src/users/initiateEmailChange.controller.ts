import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   type IUserDocument,
   type IUserEmailChangeInitiator,
   UserEmailChangeInitiatorValidator,
} from '@models/User_v3.model.ts';
import {
   EmailChangeDocumentCreateValidator,
   getEmailChangeCollection,
   type IEmailChangeDocumentCreate,
   type IEmailChangeDocumentRead,
} from '@models/EmailChange_v3.model.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { InitiateEmailChangeBody } from '@users/User_v3.schemas.ts';
import { sendEmailChangeEmails } from '@users/emailChange.email.ts';
import {
   generateRandomToken,
   generateStandardHash,
} from '@ssot/node_crypto_constants.ts';
import {
   EMAIL_CHANGE_CANCEL_EXPIRY_MS,
   EMAIL_CHANGE_CAP,
   EMAIL_CHANGE_CONFIRM_EXPIRY_MS,
} from '@ssot/user_change_constants.ts';
import { myEnv } from '../validateConfig.ts';
import { ObjectId } from 'mongodb';
import logger from '../logger.ts';
import { sanitizeError } from '@utils/sanitizeError.ts';
import {
   type StrictFindOneOptions,
   type StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';
import { isDuplicateKeyOnField } from '@utils/mongoErrors.ts';
import { USER_EMAIL_CHANGE_INITIATOR_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';
import { classifyEmailChange } from '@ssot/email_change_status_constants.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import { findEmailClaim } from '@services/emailClaim.service.ts';

const EMAIL_UNAVAILABLE_MESSAGE =
   `This email address is not available.` as const;
const EMAIL_CHANGE_REQUEST_ALREADY_ACTIVE_MESSAGE = `You already have an active email change request. Please complete or cancel it first.`;
const EMAIL_CHANGE_COOLDOWN_MESSAGE = `Your email address was changed recently. For your security, further changes are paused for a few days. You can revert the change using the cancellation link sent to your previous address.`;

export async function initiateEmailChangeController(
   req: Request,
   res: ResponseWithValidatedBody<InitiateEmailChangeBody> &
      AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { newEmail, currentPassword } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const emailChangeCollection = getEmailChangeCollection();

      const userRaw = await userCollection.findOne<IUserEmailChangeInitiator>(
         {
            _id: new ObjectId(sub),
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_EMAIL_CHANGE_INITIATOR_PROJECTION,
         } satisfies StrictFindOneOptions<IUserEmailChangeInitiator>
      );

      if (!userRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      const validatedUser = decodeStored(
         UserEmailChangeInitiatorValidator,
         userRaw,
         'email change initiator'
      );

      /* Verify the password immediately after the decode, before every guard. Otherwise Guards 2–4 ("cap reached", "address unavailable", "active change request") become a probing oracle for someone with a stolen session but no password. */
      const isPasswordValid = await verifyPassword(
         validatedUser.passwordHash,
         currentPassword
      );

      if (!isPasswordValid) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'INVALID_CREDENTIALS',
                  `Current password is incorrect.`,
                  requestId
               )
            );
      }

      /* Deliberately AFTER the credential check, mirroring loginController: revealing "deactivated" is acceptable only to someone who has just proven they know the password, and it keeps this guard from becoming a probing oracle ahead of the password check. Placed before Guard 1 so that no later guard, DB count or email can run on behalf of an inactive account. The decoded value comes from the database, not the JWT, which can be up to 60s stale. */
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

      // ── Guard 1: new email must differ from current ────────────────────────────
      if (newEmail === validatedUser.email) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `The new email address must be different from your current one.`,
                  requestId
               )
            );
      }

      // ── Guard 2: lifetime cap ──────────────────────────────────────────────────
      if (validatedUser.emailChangesUsed >= EMAIL_CHANGE_CAP) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `You have reached the maximum number of email changes (${EMAIL_CHANGE_CAP}). Please contact an administrator.`,
                  requestId
               )
            );
      }

      const now = new Date();

      // ── Guard 3: no concurrent active change for this user ─────────────────────
      await emailChangeCollection.deleteMany({
         userId: new ObjectId(sub),
         $or: [
            { cancelExpiresAt: { $lte: now } },
            { confirmedAt: null, confirmExpiresAt: { $lte: now } },
         ],
      } satisfies StrictMongoFilter<IEmailChangeDocumentRead>);

      await emailChangeCollection.deleteMany({
         newEmail,
         confirmedAt: null,
         confirmExpiresAt: { $lte: now },
      } satisfies StrictMongoFilter<IEmailChangeDocumentRead>);

      const existingChange = await loadEmailChangeStatus(
         validatedUser._id,
         now
      );

      if (existingChange.state === 'confirmed') {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  EMAIL_CHANGE_COOLDOWN_MESSAGE,
                  requestId
               )
            );
      }

      if (existingChange.state === 'pending') {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  EMAIL_CHANGE_REQUEST_ALREADY_ACTIVE_MESSAGE,
                  requestId
               )
            );
      }

      // ── Guard 4: collision check ───────────────────────────────────────────────
      /* Deliberately one message for every kind of claim. The caller can be any staff member, and distinct messages would let them probe for deactivated accounts and for other people's pending invites. */
      if ((await findEmailClaim(newEmail, now)) !== null) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  EMAIL_UNAVAILABLE_MESSAGE,
                  requestId
               )
            );
      }

      // ── Generate bilateral tokens ──────────────────────────────────────────────
      /* Two independent opaque tokens: one for confirmation (sent to new address), one for cancellation (sent to old address). Both are 48 random bytes encoded as hex. Only the SHA-256 hashes are stored. */
      const rawConfirmToken = generateRandomToken();
      const rawCancelToken = generateRandomToken();
      const confirmTokenHash = generateStandardHash(rawConfirmToken);
      const cancelTokenHash = generateStandardHash(rawCancelToken);

      const confirmExpiresAt = new Date(
         now.getTime() + EMAIL_CHANGE_CONFIRM_EXPIRY_MS
      );
      const cancelExpiresAt = new Date(
         now.getTime() + EMAIL_CHANGE_CANCEL_EXPIRY_MS
      );

      // ── Persist the EmailChange record ─────────────────────────────────────────
      const emailChangePayload: IEmailChangeDocumentCreate = {
         _id: new ObjectId(),
         confirmTokenHash,
         cancelTokenHash,
         userId: new ObjectId(sub),
         oldEmail: validatedUser.email,
         newEmail,
         confirmExpiresAt,
         cancelExpiresAt,
         confirmedAt: null,
         createdAt: now,
         updatedAt: now,
      };

      const validatedEmailChangePayload = decodeStored(
         EmailChangeDocumentCreateValidator,
         emailChangePayload,
         'email change payload'
      );

      // ── Map duplicate-key errors at insert ─────────────────────────────────────
      let emailChangeId: ObjectId;
      try {
         const insertResult = await emailChangeCollection.insertOne(
            validatedEmailChangePayload
         );
         emailChangeId = insertResult.insertedId;
      } catch (insertErr) {
         if (isDuplicateKeyOnField(insertErr, 'newEmail')) {
            return void res
               .status(409)
               .json(
                  createErrorResponse(
                     'CONFLICT',
                     EMAIL_UNAVAILABLE_MESSAGE,
                     requestId
                  )
               );
         }
         if (isDuplicateKeyOnField(insertErr, 'userId')) {
            return void res
               .status(409)
               .json(
                  createErrorResponse(
                     'CONFLICT',
                     EMAIL_CHANGE_REQUEST_ALREADY_ACTIVE_MESSAGE,
                     requestId
                  )
               );
         }
         throw insertErr;
      }

      // ── Send bilateral emails — with rollback on failure ───────────────────────
      /* An EmailChange record whose emails were never delivered is worse than no record: it silently blocks re-initiation and leaves the user with no actionable links. Rolling back removes that risk. Note that if the first email succeeds and the second fails, the first cannot be "unsent" — but deleting the record makes both raw tokens permanently inert, which is the critical safety property. */
      const confirmUrl = `${myEnv.appBaseUrl}/email-change/confirm#token=${rawConfirmToken}`;
      const cancelUrl = `${myEnv.appBaseUrl}/email-change/cancel#token=${rawCancelToken}`;

      try {
         await sendEmailChangeEmails({
            firstName: validatedUser.firstName,
            oldEmail: validatedUser.email,
            newEmail,
            confirmUrl,
            cancelUrl,
            confirmExpiresAt,
            cancelExpiresAt,
         });
      } catch (emailErr) {
         try {
            await emailChangeCollection.deleteOne({
               _id: emailChangeId,
            });
         } catch (rollbackErr) {
            logger.error(
               `Failed to roll back orphaned email change ${emailChangeId.toHexString()} after email delivery failure: ${sanitizeError(rollbackErr).message}`
            );
         }
         throw emailErr;
      }

      securityLog.record({
         event: 'EMAIL_CHANGE_REQUESTED',
         actorId: validatedUser._id,
         targetUserId: validatedUser._id,
         ...requestContext(req, res),
      });

      return void res.status(200).json({
         success: true,
         message: `Email change initiated. Check both your current and new email addresses for next steps.`,
         emailChange: classifyEmailChange(validatedEmailChangePayload, now),
      });
   } catch (err) {
      next(err);
   }
}
