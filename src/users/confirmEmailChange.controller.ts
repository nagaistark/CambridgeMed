import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import {
   EmailChangeDocumentReadValidator,
   getEmailChangeCollection,
   type IEmailChangeDocumentRead,
} from '@models/EmailChange_v3.model.ts';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import {
   getPasswordResetCollection,
   type IPasswordResetDocumentRead,
} from '@models/PasswordReset_v3.model.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';
import type { ObjectId } from 'mongodb';
import { EMAIL_CHANGE_CAP } from '@ssot/user_change_constants.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import { isDuplicateKeyOnField } from '@utils/mongoErrors.ts';
import type { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';
import type { RawTokenBody } from '@utils/effectSchemaReusables.ts';
import { withAuthTransaction } from '@utils/withAuthTransaction.ts';

type ConfirmOutcome =
   { status: 'invalid' } | { status: 'confirmed'; userId: ObjectId };

function runConfirmTransaction(tokenHash: string): Promise<ConfirmOutcome> {
   return withAuthTransaction(async (session): Promise<ConfirmOutcome> => {
      const now = new Date();

      const claimedRaw = await getEmailChangeCollection().findOneAndUpdate(
         {
            confirmTokenHash: tokenHash,
            confirmExpiresAt: { $gt: now },
            confirmedAt: null,
         } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
         {
            $set: { confirmedAt: now, updatedAt: now },
         } satisfies StrictUpdate<IEmailChangeDocumentRead>,
         { returnDocument: 'after', session }
      );

      if (claimedRaw === null) return { status: 'invalid' };

      const validatedChange = decodeStored(
         EmailChangeDocumentReadValidator,
         claimedRaw,
         'email change (confirm)'
      );

      const applied = await getUserCollection().updateOne(
         {
            _id: validatedChange.userId,
            email: validatedChange.oldEmail,
            isActive: true,
            emailChangesUsed: { $lt: EMAIL_CHANGE_CAP },
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { email: validatedChange.newEmail, updatedAt: now },
            $push: {
               previousEmails: {
                  email: validatedChange.oldEmail,
                  archivedAt: now,
               },
            },
            $inc: { emailChangesUsed: 1 },
         } satisfies StrictUpdate<IUserDocument>,
         { session }
      );

      if (applied.matchedCount === 0) {
         throw makeAppError(
            'CONCURRENCY_ERROR',
            409,
            'CONFLICT',
            `This email change can no longer be applied. Please start over.`
         );
      }

      /* "Nuclear" logout inside the transaction. All sessions must be destroyed so the user re-authenticates against the new address. Placing this inside the transaction guarantees it is rolled back if either of the writes above fails. */
      await getSessionCollection().deleteMany(
         {
            userId: validatedChange.userId,
         } satisfies StrictMongoFilter<ISessionDocument>,
         { session }
      );

      await getPasswordResetCollection().deleteMany(
         {
            userId: validatedChange.userId,
         } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
         { session }
      );

      return { status: 'confirmed', userId: validatedChange.userId };
   });
}

export async function confirmEmailChangeController(
   req: Request,
   res: ResponseWithValidatedBody<RawTokenBody>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = res.locals.validatedBody;
      const tokenHash = generateStandardHash(token);

      try {
         const result = await runConfirmTransaction(tokenHash);

         if (result.status === 'invalid') {
            return void res
               .status(404)
               .json(
                  createErrorResponse(
                     'NOT_FOUND',
                     `This link is invalid, has expired, or was already used.`,
                     requestId
                  )
               );
         }

         clearAuthCookies(res);

         securityLog.record({
            event: 'EMAIL_CHANGE_CONFIRMED',
            actorId: null, // the link works without a session
            targetUserId: result.userId,
            ...requestContext(req, res),
         });

         return void res.status(200).json({
            success: true,
            message: `Email address updated successfully. Please log in again.`,
         });
      } catch (err) {
         if (isDuplicateKeyOnField(err, 'email')) {
            return void res
               .status(409)
               .json(
                  createErrorResponse(
                     'CONFLICT',
                     `This email address is no longer available. Use the cancellation link sent to your previous address, or wait for this request to expire, then try again with a different address.`,
                     requestId
                  )
               );
         }
         throw err;
      }
   } catch (err) {
      next(err);
   }
}
