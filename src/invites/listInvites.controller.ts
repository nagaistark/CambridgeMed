import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   IUserIdName,
   UserIdNameArrayValidator,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import {
   BaseInviteItem,
   getInviteCollection,
   IAcceptedInviteItem,
   IInviteListRead,
   InviteListReadArrayValidator,
   IPendingInviteItem,
   type IInviteDocumentRead,
} from '@models/Invite_v3.model.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedQuery,
} from '@utils/customTypedResponses.ts';
import { ObjectId } from 'mongodb';
import { StrictFindOptions, StrictMongoFilter } from '@utils/pathFinder_v3.ts';
import { IObjectIdCursorPagination } from '@utils/effectSchemaReusables.ts';
import { Schema, Either } from 'effect';
import {
   INVITE_LIST_PROJECTION,
   USER_ID_NAME_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import { takePage } from '@utils/cursorPagination.ts';

type IInviteListItem = IPendingInviteItem | IAcceptedInviteItem;

export async function listInvitesController(
   _req: Request,
   res: AuthenticatedResponse &
      ResponseWithValidatedQuery<IObjectIdCursorPagination>,
   next: NextFunction
): Promise<void> {
   try {
      const { sub, role } = res.locals.authenticatedUser;
      const isSuperAdmin: boolean = role === 'superadmin';

      const { cursor, limit } = res.locals.validatedQuery;

      const inviteCollection = getInviteCollection();
      const userCollection = getUserCollection();

      // ── Build the query filter ─────────────────────────────────────────────────
      /* What we want are accepted invites (regardless of expiry) OR pending invites that haven't expired yet. The TTL janitor's ~60s lag means an expired document might still physically exist, so we filter explicitly. */
      const statusFilter = {
         $or: [
            { usedAt: { $ne: null } },
            { usedAt: null, expiresAt: { $gt: new Date() } },
         ],
      } satisfies StrictMongoFilter<IInviteDocumentRead>;

      /* Non-superadmin users only see invites they personally issued. The superadmin sees everything, so no issuedBy constraint is added. */
      const ownershipFilter = isSuperAdmin
         ? {}
         : ({
              issuedBy: new ObjectId(sub),
           } satisfies StrictMongoFilter<IInviteDocumentRead>);

      const invitesRaw = await inviteCollection
         .find<IInviteListRead>(
            {
               ...statusFilter,
               ...ownershipFilter,
               ...(cursor === undefined ? {} : { _id: { $lt: cursor } }),
            } satisfies StrictMongoFilter<IInviteDocumentRead>, // StrictMongoFilter<T> should always be built from the full collection document type, not the narrow projection type.
            {
               projection: INVITE_LIST_PROJECTION,
               sort: { _id: -1 },
               limit: limit + 1, // the +1 is the "is there a next page?" probe
               maxTimeMS: 5_000, // a runaway query dies instead of hogging the pool
            } satisfies StrictFindOptions<IInviteListRead>
         )
         .toArray();

      const { items: pageRows, hasNextPage } = takePage(invitesRaw, limit);

      if (pageRows.length === 0) {
         return void res.status(200).json({
            success: true,
            invites: [],
            pagination: { nextCursor: null, limit },
         });
      }

      // ── Validate the fetched array of invites ──────────────────────────────────
      const decodedInvites = Schema.decodeUnknownEither(
         InviteListReadArrayValidator
      )(pageRows);

      if (Either.isLeft(decodedInvites)) {
         throw decodedInvites.left;
      }

      // ── Use the validated array of invites from now on ─────────────────────────
      const validatedInvites = decodedInvites.right;

      // ── Batch-fetch accepted invitees ──────────────────────────────────────────
      /* We collect all relevant `_id`s and fetch matching users in one query. We then build an in-memory map for O(1) lookup during response assembly. */
      const acceptedByIds = validatedInvites.flatMap(inv =>
         inv.acceptedBy === null ? [] : [inv.acceptedBy]
      );

      const acceptedUsersMap = new Map<string, IUserIdName>();

      if (acceptedByIds.length > 0) {
         const acceptedUsersRaw = await userCollection
            .find<IUserIdName>(
               {
                  _id: { $in: acceptedByIds },
               } satisfies StrictMongoFilter<IUserDocument>,
               {
                  projection: USER_ID_NAME_PROJECTION,
               } satisfies StrictFindOptions<IUserIdName>
            )
            .toArray();

         const decodedAcceptedUsers = Schema.decodeUnknownEither(
            UserIdNameArrayValidator
         )(acceptedUsersRaw);
         if (Either.isLeft(decodedAcceptedUsers)) {
            throw decodedAcceptedUsers.left;
         }

         for (const user of decodedAcceptedUsers.right) {
            acceptedUsersMap.set(user._id.toHexString(), user);
         }
      }

      // ── Batch-fetch issuers (superadmin only) ──────────────────────────────────
      /* Same batch pattern. We collect unique issuedBy ObjectIds, fetch their User documents in one query, and build a map keyed by stringified id. */
      const issuerMap = new Map<string, IUserIdName>();

      if (isSuperAdmin) {
         const uniqueIssuerIds = [
            ...new Map(
               validatedInvites.map(inv => [
                  inv.issuedBy.toHexString(),
                  inv.issuedBy,
               ])
            ).values(),
         ];

         const issuersRaw = await userCollection
            .find<IUserIdName>(
               {
                  _id: { $in: uniqueIssuerIds },
               } satisfies StrictMongoFilter<IUserDocument>,
               {
                  projection: USER_ID_NAME_PROJECTION,
               } satisfies StrictFindOptions<IUserIdName> // projection: only what we need
            )
            .toArray();

         const decodedIssuers = Schema.decodeUnknownEither(
            UserIdNameArrayValidator
         )(issuersRaw);

         if (Either.isLeft(decodedIssuers)) {
            throw decodedIssuers.left;
         }

         const validatedIssuers = decodedIssuers.right;

         for (const issuer of validatedIssuers) {
            issuerMap.set(issuer._id.toHexString(), issuer);
         }
      }

      // ── Assemble the response ──────────────────────────────────────────────────
      /* Each invite is mapped to its appropriate shape based on status. The discriminated union ensures TypeScript enforces the correct fields for each branch. It's impossible to forget firstName on an accepted invite, for instance, without the compiler complaining. */
      const result: IInviteListItem[] = [];

      for (const validatedInvite of validatedInvites) {
         const _id = validatedInvite._id;
         const issuerRecord = isSuperAdmin
            ? issuerMap.get(validatedInvite.issuedBy.toString())
            : undefined;

         const base: BaseInviteItem = {
            _id,
            email: validatedInvite.email,
            role: validatedInvite.role,
            canIssueInvites: validatedInvite.canIssueInvites,
            ...(issuerRecord === undefined
               ? {}
               : {
                    issuer: {
                       _id: issuerRecord._id,
                       firstName: issuerRecord.firstName,
                       lastName: issuerRecord.lastName,
                    },
                 }),
         };

         if (validatedInvite.usedAt !== null) {
            // Accepted invite: enrich with the invitee's registered name.
            const invitee =
               validatedInvite.acceptedBy === null
                  ? undefined
                  : acceptedUsersMap.get(
                       validatedInvite.acceptedBy.toHexString()
                    );

            /* This should never be null — an accepted invite implies a User document exists. If it isn't found, we fall back to empty strings rather than throwing, since this is a list endpoint and one missing user shouldn't collapse the entire response. */
            const firstName = invitee?.firstName ?? '';
            const lastName = invitee?.lastName ?? '';

            result.push({
               ...base,
               status: 'accepted',
               firstName,
               lastName,
               usedAt: validatedInvite.usedAt,
            });
         } else {
            result.push({
               ...base,
               status: 'pending',
               expiresAt: validatedInvite.expiresAt,
            });
         }
      }

      const lastInvite = validatedInvites.at(-1);
      const nextCursor =
         hasNextPage && lastInvite !== undefined
            ? lastInvite._id.toHexString()
            : null;

      return void res.status(200).json({
         success: true,
         invites: result,
         pagination: { nextCursor, limit },
      });
   } catch (err) {
      next(err);
   }
}
