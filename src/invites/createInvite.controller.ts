import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   IUserDocument,
   IUserIdName,
   UserIdNameValidator,
} from '@models/User_v3.model.ts';
import {
   getInviteCollection,
   IInviteDocument,
   IInviteInput,
   InviteDocumentValidator,
   ISafeInvite,
} from '@models/Invite_v3.model.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { sendInviteEmail } from '@invites/invite.email.ts';
import {
   generateRandomToken,
   generateStandardHash,
} from '@ssot/node_crypto_constants.ts';
import { USER_ID_NAME_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import { myEnv } from '../validateConfig.ts';
import { CountDocumentsOptions, ObjectId } from 'mongodb';
import { buildCreateInviteResponse } from '@utils/buildResponses.ts';
import { Either, Schema } from 'effect';
import logger from '../logger.ts';
import { sanitizeError } from '../mongoDBConnect.ts';
import {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';

export async function createInviteController(
   _req: Request,
   res: ResponseWithValidatedBody<IInviteInput> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { email, role, canIssueInvites } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const inviteCollection = getInviteCollection();

      // ── Guard #1: email must not belong to an existing user ────────────────────
      /* We limit `.countDocuments()` to 1 so that it stops at the first match. */
      const existingUser =
         (await userCollection.countDocuments(
            { email } satisfies StrictMongoFilter<IUserDocument>,
            { limit: 1 } satisfies CountDocumentsOptions
         )) > 0;
      if (existingUser) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `A user with this email address already exists.`,
                  requestId
               )
            );
      }

      // ── Guard #2: no pending invite may already exist for this email ───────────
      /* countDocuments functions as `.exists()`. "Pending" = not yet accepted (usedAt is null) AND not yet expired. We filter by expiresAt explicitly because the TTL janitor runs on a background schedule and may not have cleaned up stale documents yet. */
      const existingInvite =
         (await inviteCollection.countDocuments(
            {
               email,
               usedAt: null,
               expiresAt: { $gt: new Date() },
            } satisfies StrictMongoFilter<IInviteDocument>,
            { limit: 1 } satisfies CountDocumentsOptions
         )) > 0;
      if (existingInvite) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `A pending invite for this email address already exists.`,
                  requestId
               )
            );
      }

      // ── Generate the invite token ──────────────────────────────────────────────
      /* Same strategy as refresh tokens: cryptographically random opaque bytes. The raw value travels to the invitee via email (never stored). Only the SHA-256 hash is persisted. */
      const raw = generateRandomToken(); // 96-char hex string
      const tokenHash = generateStandardHash(raw);

      // ── Calculate expiry (next Monday 00:00 Toronto time) ──────────────────────
      /* We reuse the same Monday-reset logic as refresh tokens. `refreshTokenExpirationTimestampMS` is the Unix timestamp (ms) of the next reset boundary. */
      const { refreshTokenExpirationTimestampMS } = getMaxAgeTokens();
      const expiresAt = new Date(refreshTokenExpirationTimestampMS);

      // ── Fetch issuer's full name for the email body ────────────────────────────
      /* The access token carries sub but not the name, so we need one DB hit. This should never return null since the user just passed authenticate, but we throw explicitly rather than silently continuing with a broken state. */
      const issuerRaw = await userCollection.findOne<IUserIdName>(
         {
            _id: new ObjectId(sub),
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_ID_NAME_PROJECTION,
         } satisfies StrictFindOneOptions<IUserIdName>
      );
      if (!issuerRaw) {
         throw new Error(
            `Authenticated user not found in database during invite creation. userId=${sub}`
         );
      }

      // ── Validate the fetched document against the schema ───────────────────────
      const decodedIssuer =
         Schema.decodeUnknownEither(UserIdNameValidator)(issuerRaw);
      if (Either.isLeft(decodedIssuer)) {
         throw decodedIssuer.left;
      }

      // ── Use the validated invite document from now on ──────────────────────────
      const validatedIssuer = decodedIssuer.right;

      // ── Persist the invite ─────────────────────────────────────────────────────
      const now = new Date();

      const safeInvitePayload: ISafeInvite = {
         _id: new ObjectId(),
         email,
         role,
         canIssueInvites,
         expiresAt,
         usedAt: null,
         issuedBy: new ObjectId(sub),
      };

      const fullInvitePayload: IInviteDocument = {
         ...safeInvitePayload,
         tokenHash,
         createdAt: now,
         updatedAt: now,
      };

      const decodedInvitePayload = Schema.decodeUnknownEither(
         InviteDocumentValidator
      )(fullInvitePayload);
      if (Either.isLeft(decodedInvitePayload)) {
         throw decodedInvitePayload.left;
      }

      const validatedInvite = await inviteCollection.insertOne(
         decodedInvitePayload.right
      );

      // ── Send the invite email — with rollback on failure ───────────────────────
      /* An invite whose email was never delivered is worse than no invite: it silently occupies the pending-invite slot for this address until it expires, blocking any re-invite attempt. Rolling back removes that risk. */
      const registrationUrl = `${myEnv.appBaseUrl}/register?token=${raw}`;
      try {
         await sendInviteEmail({
            to: email,
            issuerFirstName: validatedIssuer.firstName,
            issuerLastName: validatedIssuer.lastName,
            role,
            canIssueInvites,
            registrationUrl,
            expiresAt,
         });
      } catch (emailErr) {
         /* Best-effort rollback. If this deleteOne also fails, the catch-all handler will log it. The re-thrown emailErr is the primary failure. */
         try {
            await inviteCollection.deleteOne({
               _id: validatedInvite.insertedId,
            });
         } catch (rollbackErr) {
            logger.error(
               `Failed to roll back orphaned invite ${validatedInvite.insertedId.toHexString()} after email delivery failure: ${sanitizeError(rollbackErr).message}`
            );
         }
         throw emailErr;
      }

      // ── Respond ────────────────────────────────────────────────────────────────
      return void res
         .status(201)
         .json(buildCreateInviteResponse(safeInvitePayload));
   } catch (err) {
      next(err);
   }
}
