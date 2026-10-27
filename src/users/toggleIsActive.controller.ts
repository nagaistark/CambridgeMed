import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   type IUserDocument,
   type IUserIdRoleActive,
   UserIdRoleActiveValidator,
} from '@models/User_v3.model.ts';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import type { SetIsActiveBody } from '@users/User_v3.schemas.ts';
import { ClientSession, ObjectId } from 'mongodb';
import type { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import { DatabaseManager } from '../mongoDBConnect.ts';
import { USER_ID_ROLE_ACTIVE_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import {
   getInviteCollection,
   type IInviteDocumentRead,
} from '@models/Invite_v3.model.ts';
import {
   getPasswordResetCollection,
   type IPasswordResetDocumentRead,
} from '@models/PasswordReset_v3.model.ts';
import {
   getEmailChangeCollection,
   type IEmailChangeDocumentRead,
} from '@models/EmailChange_v3.model.ts';
import { allowedRoles, isAllowedRole } from '@ssot/user_roles_constants.ts';
import type { ExpandType } from '@utils/helperTypes.ts';
import logger from '../logger.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';

// ── Transaction outcome ──────────────────────────────────────────────────────────
/* Every settled result the transaction can produce. 'no_match' means the conditional update matched nothing, so NOTHING was written or swept. The controller then diagnoses why, outside the transaction. */
type ToggleOutcome =
   | { status: 'no_match' }
   | {
        status: 'applied';
        sessionsRevoked: number;
        invitesRevoked: number;
        passwordResetsRevoked: number;
        emailChangesRevoked: number;
     };

type ToggleParams = ExpandType<
   { readonly id: ObjectId } & Pick<IUserDocument, 'isActive'>
>;

async function runToggleTransaction(
   session: ClientSession,
   { id, isActive }: ToggleParams
): Promise<ToggleOutcome> {
   return session.withTransaction(async (): Promise<ToggleOutcome> => {
      // ── Atomic compare-and-swap ──────────────────────────────────────────────
      /* The filter IS the decision: "this user exists AND holds an assignable role AND is currently in the OPPOSITE state". Check and act are one indivisible step, so there is no window between "I looked" and "I wrote". The allow-list (`$in: allowedRoles`) keeps the superadmin untouchable. */
      const flipped = await getUserCollection().updateOne(
         {
            _id: id,
            role: { $in: allowedRoles },
            isActive: !isActive,
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { isActive, updatedAt: new Date() },
         } satisfies StrictUpdate<IUserDocument>,
         { session }
      );

      if (flipped.matchedCount === 0) return { status: 'no_match' };

      // Reactivation needs no sweep: the user simply logs in fresh.
      if (isActive) {
         return {
            status: 'applied',
            sessionsRevoked: 0,
            invitesRevoked: 0,
            passwordResetsRevoked: 0,
            emailChangesRevoked: 0,
         };
      }

      // ── Kill every live credential the account controls ──────────────────────
      /*      
         1. Sessions: removes the refresh-token lifeline. An already-issued access token stays valid for at most JWT_ACCESS_TOKEN_EXPIRY_MS (`authenticate` does not check `isActive`).
         2. Pending invites: an unaccepted invite is a bearer credential that outlives its issuer. Accepted invites are deliberately left alone: those people are real users now.
      */
      const sessions = await getSessionCollection().deleteMany(
         { userId: id } satisfies StrictMongoFilter<ISessionDocument>,
         { session }
      );
      const invites = await getInviteCollection().deleteMany(
         {
            issuedBy: id,
            usedAt: null,
         } satisfies StrictMongoFilter<IInviteDocumentRead>,
         { session }
      );
      const passwordResets = await getPasswordResetCollection().deleteMany(
         { userId: id } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
         { session }
      );

      /* Only UNCONFIRMED changes: those are live credentials. A confirmed change inside its revert window is a completed action whose cancel link only restores a previously known address, so it survives (same reasoning as accepted invites). */
      const emailChanges = await getEmailChangeCollection().deleteMany(
         {
            userId: id,
            confirmedAt: null,
         } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
         { session }
      );

      return {
         status: 'applied',
         sessionsRevoked: sessions.deletedCount,
         invitesRevoked: invites.deletedCount,
         passwordResetsRevoked: passwordResets.deletedCount,
         emailChangesRevoked: emailChanges.deletedCount,
      };
   });
}

// ── Controller ───────────────────────────────────────────────────────────────────
/* Authorization (MANAGE_USERS, i.e. superadmin only) is enforced at the route. This controller owns only the state transition. */
export async function toggleIsActiveController(
   req: Request,
   res: ResponseWithValidatedBody<SetIsActiveBody> &
      ResponseWithValidatedParams<IMongoIdParam> &
      AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;
      const { isActive } = res.locals.validatedBody;

      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during account status change.`
         );
      }

      // ── The write (authoritative) ──────────────────────────────────────────────
      const session = authConnection.startSession();
      let outcome: ToggleOutcome;

      try {
         outcome = await runToggleTransaction(session, { id, isActive });
      } finally {
         await session.endSession();
      }

      if (outcome.status === 'applied') {
         const log = isActive ? logger.info : logger.warn;
         log(`Account ${isActive ? 'activated' : 'deactivated'}.`, {
            requestId,
            actorId: sub,
            targetId: id.toHexString(),
            sessionsRevoked: outcome.sessionsRevoked,
            invitesRevoked: outcome.invitesRevoked,
         });

         securityLog.record({
            event: isActive ? 'ACCOUNT_ACTIVATED' : 'ACCOUNT_DEACTIVATED',
            actorId: new ObjectId(sub),
            targetUserId: id,
            ...requestContext(req, res),
         });

         return void res.status(200).json({
            success: true,
            message: `Account ${isActive ? 'activated' : 'deactivated'} successfully.`,
         });
      }

      // ── The miss path (diagnostic only) ────────────────────────────────────────
      /* The write is the authority; this read only picks the most helpful error. State may shift between the miss and this read, so the verdict is best-effort. Candid messages are fine: the caller is the superadmin. */
      const targetRaw = await getUserCollection().findOne<IUserIdRoleActive>(
         { _id: id } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_ID_ROLE_ACTIVE_PROJECTION,
         } satisfies StrictFindOneOptions<IUserIdRoleActive>
      );

      if (!targetRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `User not found.`, requestId)
            );
      }

      const decodedTarget = Schema.decodeUnknownEither(
         UserIdRoleActiveValidator
      )(targetRaw);
      if (Either.isLeft(decodedTarget)) {
         /* A stored document failing its own schema is a server-side data problem, not a client mistake. A plain Error reaches the catch-all (logged, vague 500), whereas a ParseError would be reported to the caller as a 422. */
         throw new Error(
            `Stored user ${id.toHexString()} failed validation during account status change.`,
            { cause: decodedTarget.left }
         );
      }

      const target = decodedTarget.right;

      if (!isAllowedRole(target.role)) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `This account's status cannot be changed.`,
                  requestId
               )
            );
      }

      if (target.isActive === isActive) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `This account is already ${isActive ? 'active' : 'inactive'}.`,
                  requestId
               )
            );
      }

      /* Role is assignable and the state differs, yet the update missed: another request changed the account in between. */
      return void res
         .status(409)
         .json(
            createErrorResponse(
               'CONFLICT',
               `This account was modified by another request. Please retry.`,
               requestId
            )
         );
   } catch (err) {
      next(err);
   }
}
