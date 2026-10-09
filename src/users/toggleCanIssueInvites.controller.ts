import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   type ISafeUser,
   type IUserDocument,
   type IUserInviteIssuer,
   SafeUserValidator,
   UserInviteIssuerValidator,
} from '@models/User_v3.model.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import type { SetCanIssueInvitesBody } from '@users/User_v3.schemas.ts';
import {
   arePermissionsValidForRole,
   Permissions,
} from '@ssot/permissions_constants.ts';
import { ObjectId } from 'mongodb';
import type { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import type { NonNullableProps } from '@utils/helperTypes.ts';
import { Either, Schema } from 'effect';
import {
   SAFE_USER_PROJECTION,
   USER_INVITE_ISSUER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';

export async function toggleCanIssueInvitesController(
   _req: Request,
   res: ResponseWithValidatedBody<SetCanIssueInvitesBody> &
      ResponseWithValidatedParams<IMongoIdParam> &
      AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;
      const { canIssueInvites } = res.locals.validatedBody;

      const userCollection = getUserCollection();

      /* The caller's visibility scope. Superadmin may manage anyone. Everyone else only the users they personally invited (a one-level, permanent accountability link). Every query below spreads this in, so "not yours" is structurally identical to "doesn't exist". */
      type ScopeFilter =
         | Record<string, never>
         | NonNullableProps<Pick<IUserDocument, 'invitedBy'>>;

      const scopeFilter: ScopeFilter =
         role === 'superadmin' ? {} : { invitedBy: new ObjectId(sub) };

      // ── Scoped fetch ───────────────────────────────────────────────────────────
      const targetUserRaw = await userCollection.findOne<ISafeUser>(
         {
            _id: id,
            ...scopeFilter,
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: SAFE_USER_PROJECTION,
         } satisfies StrictFindOneOptions<ISafeUser>
      );

      if (!targetUserRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `User not found.`, requestId)
            );
      }

      /* We consume `role` and `permissions` below, so the decode stays. */
      const decodedTargetUser =
         Schema.decodeUnknownEither(SafeUserValidator)(targetUserRaw);

      if (Either.isLeft(decodedTargetUser)) {
         throw decodedTargetUser.left;
      }

      const validatedTargetUser = decodedTargetUser.right;

      // ── No-op guard ────────────────────────────────────────────────────────────
      const currentlyHas =
         (validatedTargetUser.permissions & Permissions.ISSUE_INVITES) !== 0;

      if (currentlyHas === canIssueInvites) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `This user's invite privilege is already set to ${canIssueInvites}.`,
                  requestId
               )
            );
      }

      // ── Role ceiling ───────────────────────────────────────────────────────────
      /* Safe to be candid here: the caller is already authorized to see this user. */
      const newPermissions = canIssueInvites
         ? validatedTargetUser.permissions | Permissions.ISSUE_INVITES
         : validatedTargetUser.permissions & ~Permissions.ISSUE_INVITES;

      if (
         !arePermissionsValidForRole(validatedTargetUser.role, newPermissions)
      ) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `Invite privileges cannot be ${canIssueInvites ? 'granted to' : 'revoked from'} a ${validatedTargetUser.role}.`,
                  requestId
               )
            );
      }

      // ── Grant guard ────────────────────────────────────────────────────────────────
      /* You cannot hand out a privilege you do not currently hold. Revocations are exempt. */
      if (canIssueInvites) {
         const callerRaw = await userCollection.findOne<IUserInviteIssuer>(
            {
               _id: new ObjectId(sub),
            } satisfies StrictMongoFilter<IUserDocument>,
            {
               projection: USER_INVITE_ISSUER_PROJECTION,
            } satisfies StrictFindOneOptions<IUserInviteIssuer>
         );
         if (!callerRaw) {
            throw new Error(
               `Authenticated user not found in database during invite-privilege grant. userId=${sub}`
            );
         }

         const decodedCaller = Schema.decodeUnknownEither(
            UserInviteIssuerValidator
         )(callerRaw);
         if (Either.isLeft(decodedCaller)) {
            throw decodedCaller.left;
         }

         const caller = decodedCaller.right;
         if (
            !caller.isActive ||
            (caller.permissions & Permissions.ISSUE_INVITES) === 0
         ) {
            return void res
               .status(403)
               .json(
                  createErrorResponse(
                     'FORBIDDEN',
                     `You cannot grant a privilege you do not hold.`,
                     requestId
                  )
               );
         }
      }

      // ── Compare-and-swap write ─────────────────────────────────────────────────
      /* The filter says "only if the document still looks the way I decided on, and I'm still allowed to touch it". */
      const updateResult = await userCollection.updateOne(
         {
            _id: validatedTargetUser._id,
            permissions: validatedTargetUser.permissions,
            ...scopeFilter,
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { permissions: newPermissions },
         } satisfies StrictUpdate<IUserDocument>
      );

      if (updateResult.matchedCount === 0) {
         throw makeAppError(
            'CONCURRENCY_ERROR',
            409,
            'CONFLICT',
            `This user's permissions were changed by another request. Please retry.`
         );
      }

      return void res.status(200).json({
         success: true,
         message: `Invite privilege ${canIssueInvites ? 'granted' : 'revoked'} successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
