import type { Request, Response, NextFunction } from 'express';
import {
   getInviteCollection,
   type IInviteDocumentRead,
   type IInvitePreview,
   InvitePreviewValidator,
} from '@models/Invite_v3.model.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import { buildPreviewInviteResponse } from '@utils/buildResponses.ts';
import { INVITE_PREVIEW_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';

// Declare the param shape so `token` is narrowed to `string`:
type PreviewInviteParams = { token: string };

export async function previewInviteController(
   req: Request<PreviewInviteParams>,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = req.params;

      // ── Hash and look up ───────────────────────────────────────────────────────
      const tokenHash = generateStandardHash(token);
      const inviteRaw = await getInviteCollection().findOne<IInvitePreview>(
         { tokenHash } satisfies StrictMongoFilter<IInviteDocumentRead>,
         {
            projection: INVITE_PREVIEW_PROJECTION,
         } satisfies StrictFindOneOptions<IInvitePreview>
      );

      // ── Existence check ────────────────────────────────────────────────────────
      if (!inviteRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `This invite link is invalid.`,
                  requestId
               )
            );
      }

      // ── Validate the fetched safe invite against the schema ────────────────────
      const decodedSafeInvite = Schema.decodeUnknownEither(
         InvitePreviewValidator
      )(inviteRaw);

      if (Either.isLeft(decodedSafeInvite)) {
         throw decodedSafeInvite.left;
      }

      // ── Use the validated safe invite from now on ──────────────────────────────
      const validatedInvitePreview = decodedSafeInvite.right;

      // ── Expiry check ───────────────────────────────────────────────────────────
      /* We check expiresAt even if the document exists, because MongoDB's TTL janitor runs on a background thread and may lag by up to a minute. This ensures the response is always logically correct, not just contingent on when the janitor last ran. */
      if (validatedInvitePreview.expiresAt <= new Date()) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `This invite link has expired.`,
                  requestId
               )
            );
      }

      // ── Already-accepted check ─────────────────────────────────────────────────
      if (validatedInvitePreview.usedAt !== null) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `This invite has already been accepted.`,
                  requestId
               )
            );
      }

      // ── Return the safe preview ────────────────────────────────────────────────
      return void res
         .status(200)
         .json(buildPreviewInviteResponse(validatedInvitePreview));
   } catch (err) {
      next(err);
   }
}
