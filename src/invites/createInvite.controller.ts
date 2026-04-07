import type { Request, NextFunction } from 'express';
import mongoose from 'mongoose';
import { randomBytes, createHash } from 'node:crypto';
import { getUserModel } from '@models/User.model.ts';
import {
   getInviteModel,
   type IInviteCreateBody,
} from '@models/Invite.model.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import { TypedResponse } from '@utils/typedResponse.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { sendInviteEmail } from '@invites/invite.email.ts';
import { myEnv } from 'validateConfig.ts';

export async function createInviteController(
   _req: Request,
   res: TypedResponse<IInviteCreateBody>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser!;
      const { email, role, canIssueInvites } = res.locals.validatedBody;

      const User = getUserModel();
      const Invite = getInviteModel();

      // ── Guard #1: email must not belong to an existing user ────────────────────
      /* `.exists()` returns the document's `_id` if found, or null — far cheaper than a full `.findOne()` since it stops at the first match. */
      const existingUser = await User.exists({ email });
      if (existingUser) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `A user with this email address already exists.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Guard #2: no pending invite may already exist for this email ───────────
      /* "Pending" = not yet accepted (usedAt is null) AND not yet expired. We filter by expiresAt explicitly because the TTL janitor runs on a background schedule and may not have cleaned up stale documents yet. */
      const existingInvite = await Invite.exists({
         email,
         usedAt: null,
         expiresAt: { $gt: new Date() },
      });
      if (existingInvite) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `A pending invite for this email address already exists.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Generate the invite token ──────────────────────────────────────────────
      /* Same strategy as refresh tokens: cryptographically random opaque bytes. The raw value travels to the invitee via email (never stored). Only the SHA-256 hash is persisted. */
      const raw = randomBytes(48).toString('hex'); // 96-char hex string
      const tokenHash = createHash('sha256').update(raw).digest('hex');

      // ── Calculate expiry (next Monday 00:00 Toronto time) ──────────────────────
      /* We reuse the same Monday-reset logic as refresh tokens. RTEXP is the Unix timestamp (ms) of the next reset boundary. */
      const { RTEXP } = getMaxAgeTokens();
      const expiresAt = new Date(RTEXP);

      // ── Fetch issuer's full name for the email body ────────────────────────────
      /* The access token carries sub but not the name, so we need one DB hit. This should never return null since the user just passed authenticate, but we throw explicitly rather than silently continuing with a broken state. */
      const issuer = await User.findById(sub).lean();
      if (!issuer) {
         throw new Error(
            `Authenticated user not found in database during invite creation. userId=${sub}`
         );
      }

      // ── Persist the invite ─────────────────────────────────────────────────────
      const invite = await Invite.create({
         email,
         role,
         canIssueInvites,
         tokenHash,
         expiresAt,
         usedAt: null,
         issuedBy: new mongoose.Types.ObjectId(sub),
      });

      // ── Send the invite email — with rollback on failure ───────────────────────
      /* An invite whose email was never delivered is worse than no invite: it silently occupies the pending-invite slot for this address until it expires, blocking any re-invite attempt. Rolling back removes that risk. */
      const registrationUrl = `${myEnv.appBaseUrl}/register?token=${raw}`;
      try {
         await sendInviteEmail({
            to: email,
            issuerFirstName: issuer.firstName,
            issuerLastName: issuer.lastName,
            role,
            canIssueInvites,
            registrationUrl,
            expiresAt,
         });
      } catch (emailErr) {
         /* Best-effort rollback. If this deleteOne also fails, the catch-all handler will log it. The re-thrown emailErr is the primary failure. */
         await Invite.deleteOne({ _id: invite._id }).catch(() => undefined);
         throw emailErr;
      }

      // ── Respond ────────────────────────────────────────────────────────────────
      /* Return a safe subset — never expose tokenHash or issuedBy internals. */
      const response = {
         success: true as const,
         message: 'Invite sent successfully.',
         invite: {
            id: invite._id,
            email: invite.email,
            role: invite.role,
            canIssueInvites: invite.canIssueInvites,
            expiresAt: invite.expiresAt,
         },
      };
      return void res.status(201).json(response);
   } catch (err) {
      next(err);
   }
}
