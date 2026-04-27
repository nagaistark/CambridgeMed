import type { Request, Response, NextFunction } from 'express';
import { getInviteModel } from '@models/Invite.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   generateStandardHash,
   HEX96_REGEX,
} from '@ssot/node_crypto_constants.ts';

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

      // ── Token format check ─────────────────────────────────────────────────────
      /* We respond with 404 (not 400) because we don't want to leak that token format is being validated — a malformed token is indistinguishable from a non-existent one from the caller's perspective. */
      if (!HEX96_REGEX.test(token)) {
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

      // ── Hash and look up ───────────────────────────────────────────────────────
      const tokenHash = generateStandardHash(token);
      const Invite = getInviteModel();
      const invite = await Invite.findOne({ tokenHash }).lean();

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
      /* We deliberately omit tokenHash, issuedBy, _id, and timestamps. The raw token is already in the URL — there is no reason to echo it back. The frontend uses this response to render a personalised registration form. */
      return void res.status(200).json({
         success: true,
         invite: {
            email: invite.email,
            role: invite.role,
            canIssueInvites: invite.canIssueInvites,
            expiresAt: invite.expiresAt,
         },
      });
   } catch (err) {
      next(err);
   }
}
