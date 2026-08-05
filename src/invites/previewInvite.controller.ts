import type { Request, Response, NextFunction } from 'express';
import {
   getInviteCollection,
   IInviteDocument,
} from '@models/Invite_v3.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import { buildPreviewInviteResponse } from '@utils/buildResponses.ts';
import { SAFE_INVITE_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';

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
      const invite = await getInviteCollection().findOne(
         { tokenHash } satisfies StrictMongoFilter<IInviteDocument>,
         {
            projection: SAFE_INVITE_PROJECTION,
         } satisfies StrictFindOneOptions<IInviteDocument>
      );

      // ── Existence and expiry check ─────────────────────────────────────────────
      /* We check expiresAt even if the document exists, because MongoDB's TTL janitor runs on a background thread and may lag by up to a minute. This ensures the response is always logically correct, not just contingent on when the janitor last ran. */
      if (!invite || invite.expiresAt <= new Date()) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `This invite link is invalid or has expired.`,
                  requestId
               )
            );
      }

      // ── Already-accepted check ─────────────────────────────────────────────────
      if (invite.usedAt !== null) {
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
      return void res.status(200).json(buildPreviewInviteResponse(invite));
   } catch (err) {
      next(err);
   }
}
