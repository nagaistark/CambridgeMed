import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   type IUserDocument,
   type IUserEmailChangeInitiator,
   UserEmailChangeInitiatorValidator,
} from '@models/User_v3.model.ts';
import {
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
   EMAIL_CHANGE_CAP,
   EMAIL_CHANGE_TOKEN_EXPIRY_MS,
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

const EMAIL_ALREADY_CLAIMED_CONFLICT_MESSAGE = `This email address is already claimed by a pending change request.`;
const EMAIL_CHANGE_REQUEST_ALREADY_ACTIVE_MESSAGE = `You already have an active email change request. Please complete or cancel it first.`;

export async function initiateEmailChangeController(
   _req: Request,
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
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Current password is incorrect.`,
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
               expiresAt: { $gt: now },
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
      /* Reap anything for this user that has already logically expired but hasn't yet been swept by MongoDB's TTL monitor (which runs on its own ~60s cycle). Both unique indexes are clock-blind: a logically dead document keeps blocking inserts until the TTL monitor (~60s cycle) removes it. One sweep per index, each mirroring that index's coverage. */

      await emailChangeCollection.deleteMany({
         userId: new ObjectId(sub),
         expiresAt: { $lte: now },
      } satisfies StrictMongoFilter<IEmailChangeDocumentRead>);

      await emailChangeCollection.deleteMany({
         newEmail,
         confirmedAt: null,
         expiresAt: { $lte: now },
      } satisfies StrictMongoFilter<IEmailChangeDocumentRead>);

      const userHasActiveChange =
         (await emailChangeCollection.countDocuments(
            {
               userId: new ObjectId(sub),
               expiresAt: { $gt: now },
            } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
            { limit: 1 } satisfies CountDocumentsOptions
         )) > 0;

      if (userHasActiveChange) {
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

      const expiresAt = new Date(Date.now() + EMAIL_CHANGE_TOKEN_EXPIRY_MS);

      // ── Persist the EmailChange record ─────────────────────────────────────────
      const emailChangePayload: IEmailChangeDocumentCreate = {
         _id: new ObjectId(),
         confirmTokenHash,
         cancelTokenHash,
         userId: new ObjectId(sub),
         oldEmail: validatedUser.email,
         newEmail,
         expiresAt,
         confirmedAt: null,
         createdAt: now,
         updatedAt: now,
      };

      // ── Map duplicate-key errors at insert ─────────────────────────────────────
      let emailChangeId: ObjectId;
      try {
         const insertResult =
            await emailChangeCollection.insertOne(emailChangePayload);
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
            expiresAt,
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

      return void res.status(200).json({
         success: true,
         message: `Email change initiated. Check both your current and new email addresses for next steps.`,
      });
   } catch (err) {
      next(err);
   }
}
