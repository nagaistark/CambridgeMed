import type { Request, NextFunction } from 'express';
import { createHash } from 'node:crypto';
import mongoose from 'mongoose';
import { DatabaseManager } from 'dbConnect.ts';
import {
   getUserModel,
   type IUserInitial,
   type IUserDefinition,
} from '@models/User.model.ts';
import {
   getInviteModel,
   type IInviteDefinition,
} from '@models/Invite.model.ts';
import { hashPassword } from '@utils/hashAndVerify.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';
import { HEX96_REGEX } from '@ssot/node_crypto_constants.ts';

type AcceptInviteParams = { token: string };

// ── Transaction outcome ──────────────────────────────────────────────────────────
/* A discriminated union describing every meaningful result the transaction can produce. Each member is identifiable by its `status` field, which TypeScript uses to narrow the type in conditional branches. There is no 'pending' member — every outcome that leaves this module is a genuine, settled result. */
type TransactionOutcome =
   | { status: 'success' }
   | { status: 'invalid_token' }
   | { status: 'email_mismatch' };

// ── A private error class ────────────────────────────────────────────────────────
/* Used exclusively to signal a deliberate abort from inside the withTransaction() callback. It carries the outcome so the catch block outside can read it and set the sentinel accordingly. It is intentionally not exported — nothing outside this file should ever need to catch or construct one of these. */
class TransactionAbortError extends Error {
   constructor(public readonly outcome: TransactionOutcome) {
      super(`Transaction deliberately aborted: ${outcome.status}`);
      this.name = 'TransactionAbortError';
   }
}

// ── Transaction helper ───────────────────────────────────────────────────────────
/* Extracting the transactional work into its own function serves two purposes. First, it gives TypeScript a concrete Promise<TransactionOutcome> return type to reason about, which eliminates the "used before assigned" ambiguity that arises when outcome is mutated inside a withTransaction() callback. Second, it enforces the separation of concerns that the sentinel pattern was aiming for conventionally — the controller owns the HTTP layer, and this function owns the database layer. That boundary is now structural, not just a matter of convention.

The 'invalid_token' default inside this function is genuinely justified: it is the function's honest fallback for the case where withTransaction() aborts without the callback having had the chance to set a more specific outcome — for example, if findOneAndUpdate returns null. */

type RegistrationParams = Pick<
   IUserDefinition,
   'firstName' | 'lastName' | 'passwordHash'
> &
   Pick<IInviteDefinition, 'email' | 'tokenHash'>;

async function runRegistrationTransaction(
   session: mongoose.ClientSession,
   params: RegistrationParams
): Promise<TransactionOutcome> {
   const { tokenHash, email, firstName, lastName, passwordHash } = params;
   let outcome: TransactionOutcome = { status: 'invalid_token' };

   try {
      await session.withTransaction(async () => {
         const Invite = getInviteModel();
         const User = getUserModel();

         // ── Atomic claim ────────────────────────────────────────────────────────
         /* The filter's three conditions must ALL be true simultaneously:
            - tokenHash matches → correct invite
            - usedAt is null    → not yet accepted
            - expiresAt > now   → not expired, regardless of TTL janitor lag
   
         If withTransaction() retries this callback after a transient error, it will have already rolled back the previous attempt's writes, leaving usedAt null and ready to be claimed cleanly on the retry. */
         const claimedInvite = await Invite.findOneAndUpdate(
            { tokenHash, usedAt: null, expiresAt: { $gt: new Date() } },
            { $set: { usedAt: new Date() } },
            { new: true, session }
         ).lean();

         if (!claimedInvite) {
            throw new TransactionAbortError({ status: 'invalid_token' });
         }

         // ── Email confirmation check ────────────────────────────────────────────
         /* We compare the body email against claimedInvite.email (the value locked in at invite creation time) to confirm the registering person is the intended recipient.
   
         If mismatch, set the outcome BEFORE returning. withTransaction() aborts, rolling back the findOneAndUpdate above and leaving usedAt as null. The invite is fully unclaimed and reusable. */
         if (claimedInvite.email !== email) {
            throw new TransactionAbortError({ status: 'email_mismatch' });
         }

         // ── Create the User document ────────────────────────────────────────────
         /* The email we persist is claimedInvite.email, not the "body" email. The body email has served its purpose in the confirmation check and is now discarded. role, canIssueInvites, and invitedBy come from the invite document and are not negotiable by the registering user. Mongoose's create() with a session requires the array signature and returns an array of the created documents. We discard the return value because our response carries no user data. */
         await User.create(
            [
               {
                  firstName,
                  lastName,
                  email: claimedInvite.email,
                  passwordHash,
                  role: claimedInvite.role,
                  canIssueInvites: claimedInvite.canIssueInvites,
                  invitedBy: claimedInvite.issuedBy,
                  isActive: true,
               },
            ],
            { session }
         );

         outcome = { status: 'success' };
         // withTransaction() commits automatically when the callback resolves.
      });
   } catch (err) {
      if (err instanceof TransactionAbortError) {
         /* This is a deliberate, expected abort. Set the outcome and let the function return normally — this is not an error condition from the controller's perspective. */
         outcome = err.outcome;
      } else {
         throw err;
      }
   }

   return outcome;
}

// ── Controller ───────────────────────────────────────────────────────────────────
export async function acceptInviteController(
   req: Request<AcceptInviteParams>,
   res: ResponseWithValidatedBody<IUserInitial>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = req.params;
      const { email, firstName, lastName, password } = res.locals.validatedBody;

      // ── Step 1: Token format check ─────────────────────────────────────────────
      /* 404 rather than 400, so a malformed token is indistinguishable from a non-existent one. We don't want to leak that format validation is occurring. */
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

      // ── Step 2: Hash the password BEFORE opening the transaction ───────────────
      /* Keeping a MongoDB transaction open while Argon2 churns for 100–300ms would hold server-side resources unnecessarily. */
      const passwordHash = await hashPassword(password);

      // ── Step 3: Derive the token hash ──────────────────────────────────────────
      const tokenHash = createHash('sha256').update(token).digest('hex');

      // ── Step 4: Acquire the auth connection ────────────────────────────────────
      /* The server bootstrap guarantees this is never null, and any unexpected throw here is caught by the outer try/catch. */
      const authConnection = DatabaseManager.getInstance().auth.connection;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during invite acceptance.`
         );
      }

      // ── Step 5: Run the transaction ────────────────────────────────────────────
      const session = await authConnection.startSession();

      /* The try/finally here guarantees that session.endSession() always runs, regardless of whether the transaction committed, aborted, or threw unexpectedly. */
      let outcome: TransactionOutcome;
      try {
         outcome = await runRegistrationTransaction(session, {
            tokenHash,
            email,
            firstName,
            lastName,
            passwordHash,
         });
      } finally {
         await session.endSession();
      }

      // ── Step 6: Send the HTTP response ─────────────────────────────────────────
      if (outcome.status === 'invalid_token') {
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

      if (outcome.status === 'email_mismatch') {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `The email address you entered does not match the one this invite was sent to.`,
                  requestId
               )
            );
      }

      /* outcome.status === 'success' 201 Created. Minimal payload (no user data, no tokens). The client redirects to the login page. The full user lifecycle is now complete: invited → registered → ready to authenticate. */
      return void res.status(201).json({
         success: true,
         message: `Registration successful. You may now log in.`,
      });
   } catch (err) {
      next(err);
   }
}
