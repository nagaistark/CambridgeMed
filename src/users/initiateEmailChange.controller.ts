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
import { type CountDocumentsOptions, ObjectId } from 'mongodb';
import logger from '../logger.ts';
import { sanitizeError } from '../mongoDBConnect.ts';
import {
   type StrictFindOneOptions,
   type StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';
import { isDuplicateKeyOnField } from '@utils/mongoErrors.ts';
import { Either, Schema } from 'effect';
import { USER_EMAIL_CHANGE_INITIATOR_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';
import { classifyEmailChange } from '@ssot/email_change_status_constants.ts';

const EMAIL_ALREADY_CLAIMED_CONFLICT_MESSAGE = `This email address is already claimed by a pending change request.`;
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

      const decodedUser = Schema.decodeUnknownEither(
         UserEmailChangeInitiatorValidator
      )(userRaw);

      if (Either.isLeft(decodedUser)) {
         throw decodedUser.left;
      }

      const validatedUser = decodedUser.right;

      /* Verify the password immediately after the decode, before every guard. Otherwise Guards 2–5 ("cap reached", "email already exists", "claimed by pending change") become a probing oracle for someone with a stolen session but no password. */
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

      // ── Guard 3: new email must not belong to an existing user ─────────────────
      /* Again, `.countDocuments` functions as `.exists()` here. */
      const emailTaken =
         (await userCollection.countDocuments(
            { email: newEmail } satisfies StrictMongoFilter<IUserDocument>,
            { limit: 1 } satisfies CountDocumentsOptions
         )) > 0;

      if (emailTaken) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `An account with this email address already exists.`,
                  requestId
               )
            );
      }

      const now = new Date();

      // ── Guard 4: new email must not be claimed by another pending change ───────
      /* Between the moment a change is initiated and the moment the confirmation link is clicked, the newEmail is not yet stored on any User document. We close that gap here. Only unconfirmed, non-cancelled, non-expired changes are "active". */
      const emailClaimedByPendingChange =
         (await emailChangeCollection.countDocuments(
            {
               newEmail,
               confirmedAt: null,
               confirmExpiresAt: { $gt: now },
            } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
            { limit: 1 } satisfies CountDocumentsOptions
         )) > 0;
      if (emailClaimedByPendingChange) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  EMAIL_ALREADY_CLAIMED_CONFLICT_MESSAGE,
                  requestId
               )
            );
      }

      // ── Guard 5: no concurrent active change for this user ─────────────────────
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

      const decodedEmailChangePayload = Schema.decodeUnknownEither(
         EmailChangeDocumentCreateValidator
      )(emailChangePayload);

      if (Either.isLeft(decodedEmailChangePayload)) {
         throw decodedEmailChangePayload.left;
      }

      const validatedEmailChangePayload = decodedEmailChangePayload.right;

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
                     EMAIL_ALREADY_CLAIMED_CONFLICT_MESSAGE,
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
      const confirmUrl = `${myEnv.appBaseUrl}/email-change/confirm/${rawConfirmToken}`;
      const cancelUrl = `${myEnv.appBaseUrl}/email-change/cancel/${rawCancelToken}`;

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
