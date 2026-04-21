import type { Request, NextFunction } from 'express';
import { randomBytes, createHash } from 'node:crypto';
import mongoose from 'mongoose';
import { getUserModel } from '@models/User.model.ts';
import { getEmailChangeModel } from '@models/EmailChange.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { TypedResponse } from '@utils/typedResponse.ts';
import type { InitiateEmailChangeBody } from '@users/User.schemas.ts';
import { sendEmailChangeEmails } from '@users/emailChange.email.ts';
import {
   EMAIL_CHANGE_CAP,
   EMAIL_CHANGE_TOKEN_EXPIRY_MS,
} from '@ssot/user_change_constants.ts';
import { myEnv } from 'validateConfig.ts';

export async function initiateEmailChangeController(
   _req: Request,
   res: TypedResponse<InitiateEmailChangeBody>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser!;
      const { newEmail } = res.locals.validatedBody;

      const User = getUserModel();
      const EmailChange = getEmailChangeModel();

      const user = await User.findById(sub).lean();
      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `Account not found.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Guard 1: new email must differ from current ────────────────────────────
      if (newEmail === user.email) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `The new email address must be different from your current one.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Guard 2: lifetime cap ──────────────────────────────────────────────────
      if (user.emailChangesUsed >= EMAIL_CHANGE_CAP) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `You have reached the maximum number of email changes (${EMAIL_CHANGE_CAP}). Please contact an administrator.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Guard 3: new email must not belong to an existing user ─────────────────
      const emailTaken = await User.exists({ email: newEmail });
      if (emailTaken) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `An account with this email address already exists.`,
                  undefined,
                  requestId
               )
            );
      }

      const now = new Date();

      // ── Guard 4: new email must not be claimed by another pending change ───────
      /* Between the moment a change is initiated and the moment the confirmation link is clicked, the newEmail is not yet stored on any User document (so the User.exists check above would miss it). We close that gap here. Only unconfirmed, non-cancelled, non-expired changes are "active". */
      const emailClaimedByPendingChange = await EmailChange.exists({
         newEmail,
         confirmedAt: null,
         expiresAt: { $gt: now },
      });
      if (emailClaimedByPendingChange) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `This email address is already claimed by a pending change request.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Guard 5: no concurrent active change for this user ─────────────────────
      /* Only one active (non-expired) email change per user at a time is allowed. Active = confirmed-but-still-cancellable. */
      const userHasActiveChange = await EmailChange.exists({
         userId: new mongoose.Types.ObjectId(sub),
         confirmedAt: { $ne: null },
         expiresAt: { $gt: now },
      });
      if (userHasActiveChange) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `You already have an active email change request. Please complete or cancel it first.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Generate bilateral tokens ──────────────────────────────────────────────
      /* Two independent opaque tokens: one for confirmation (sent to new address), one for cancellation (sent to old address). Both are 48 random bytes encoded as hex. Only the SHA-256 hashes are stored. */
      const rawConfirmToken = randomBytes(48).toString('hex');
      const rawCancelToken = randomBytes(48).toString('hex');
      const confirmTokenHash = createHash('sha256')
         .update(rawConfirmToken)
         .digest('hex');
      const cancelTokenHash = createHash('sha256')
         .update(rawCancelToken)
         .digest('hex');

      const expiresAt = new Date(Date.now() + EMAIL_CHANGE_TOKEN_EXPIRY_MS);

      // ── Persist the EmailChange record ─────────────────────────────────────────
      const emailChange = await EmailChange.create({
         confirmTokenHash,
         cancelTokenHash,
         userId: new mongoose.Types.ObjectId(sub),
         oldEmail: user.email,
         newEmail,
         expiresAt,
         confirmedAt: null,
      });

      // ── Send bilateral emails — with rollback on failure ───────────────────────
      /* An EmailChange record whose emails were never delivered is worse than no record: it silently blocks re-initiation and leaves the user with no actionable links. Rolling back removes that risk. Note that if the first email succeeds and the second fails, the first cannot be "unsent" — but deleting the record makes both raw tokens permanently inert, which is the critical safety property. */
      const confirmUrl = `${myEnv.appBaseUrl}/email-change/confirm/${rawConfirmToken}`;
      const cancelUrl = `${myEnv.appBaseUrl}/email-change/cancel/${rawCancelToken}`;

      try {
         await sendEmailChangeEmails({
            firstName: user.firstName,
            oldEmail: user.email,
            newEmail,
            confirmUrl,
            cancelUrl,
            expiresAt,
         });
      } catch (emailErr) {
         await EmailChange.deleteOne({ _id: emailChange._id }).catch(
            () => undefined
         );
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
