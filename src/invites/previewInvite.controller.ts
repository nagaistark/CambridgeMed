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
import { decodeStored } from '@utils/decodeStored.ts';

// Declare the param shape so `token` is narrowed to `string`:
type PreviewInviteParams = { token: string };

const INVALID_LINK_MESSAGE =
   `This invite link is invalid or has expired.` as const;

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
         {
            tokenHash,
            usedAt: null,
            expiresAt: { $gt: new Date() },
         } satisfies StrictMongoFilter<IInviteDocumentRead>,
         {
            projection: INVITE_PREVIEW_PROJECTION,
         } satisfies StrictFindOneOptions<IInvitePreview>
      );

      if (inviteRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', INVALID_LINK_MESSAGE, requestId)
            );
      }

      // ── Validate the fetched safe invite against the schema ────────────────────
      const validatedInvitePreview = decodeStored(
         InvitePreviewValidator,
         inviteRaw,
         'invite preview'
      );

      // ── Return the safe preview ────────────────────────────────────────────────
      return void res
         .status(200)
         .json(buildPreviewInviteResponse(validatedInvitePreview));
   } catch (err) {
      next(err);
   }
}
