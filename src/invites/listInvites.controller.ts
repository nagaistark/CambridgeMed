import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   IAcceptedUser,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import {
   BaseInviteItem,
   getInviteCollection,
   IAcceptedInviteItem,
   IInviteIssuer,
   InviteDocumentArrayValidator,
   IPendingInviteItem,
   type IInviteDocument,
} from '@models/Invite_v3.model.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { ObjectId } from 'mongodb';
import { StrictFindOptions, StrictMongoFilter } from '@utils/pathFinder_v3.ts';
import { Schema, Either } from 'effect';

type IInviteListItem = IPendingInviteItem | IAcceptedInviteItem;

export async function listInvitesController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const { sub, role } = res.locals.authenticatedUser;
      const isSuperAdmin: boolean = role === 'superadmin';

      const inviteCollection = getInviteCollection();
      const userCollection = getUserCollection();

      // ── Build the query filter ─────────────────────────────────────────────────
      /* What we want are accepted invites (regardless of expiry) OR pending invites that haven't expired yet. The TTL janitor's ~60s lag means an expired document might still physically exist, so we filter explicitly. */
      const statusFilter = {
         $or: [
            { usedAt: { $ne: null } },
            { usedAt: null, expiresAt: { $gt: new Date() } },
         ],
      } satisfies StrictMongoFilter<IInviteDocument>;

      /* Non-superadmin users only see invites they personally issued. The superadmin sees everything, so no issuedBy constraint is added. */
      const ownershipFilter = isSuperAdmin
         ? {}
         : ({
              issuedBy: new ObjectId(sub),
           } satisfies StrictMongoFilter<IInviteDocument>);

      const invitesRaw = await inviteCollection
         .find({
            ...statusFilter,
            ...ownershipFilter,
         } satisfies StrictMongoFilter<IInviteDocument>)
         .toArray();

      if (invitesRaw.length === 0) {
         return void res.status(200).json({
            success: true,
            invites: [],
         });
      }

      // ── Validate the fetched array of invites ──────────────────────────────────
      const decodedInvites = Schema.decodeUnknownEither(
         InviteDocumentArrayValidator
      )(invitesRaw);

      if (Either.isLeft(decodedInvites)) {
         throw decodedInvites.left;
      }

      // ── Use the validated array of invites from now on ─────────────────────────
      const validatedInvites = decodedInvites.right;

      // ── Batch-fetch accepted invitees ──────────────────────────────────────────
      /* We collect all relevant emails and fetch matching users in one query. We then build an in-memory map for O(1) lookup during response assembly. */
      const acceptedEmails = validatedInvites
         .filter(inv => inv.usedAt !== null)
         .map(inv => inv.email);

      const acceptedUsersMap = new Map<
         string,
         { firstName: string; lastName: string }
      >();

      if (acceptedEmails.length > 0) {
         const acceptedUsers = await userCollection
            .find<IAcceptedUser>(
               {
                  email: { $in: acceptedEmails },
               } satisfies StrictMongoFilter<IUserDocument>,
               {
                  projection: { email: 1, firstName: 1, lastName: 1 },
               } satisfies StrictFindOptions<IAcceptedUser> // projection: fetch only what we need
            )
            .toArray();

         for (const user of acceptedUsers) {
            acceptedUsersMap.set(user.email, {
               firstName: user.firstName,
               lastName: user.lastName,
            });
         }
      }

      // ── Batch-fetch issuers (superadmin only) ──────────────────────────────────
      /* Same batch pattern. We collect unique issuedBy ObjectIds, fetch their User documents in one query, and build a map keyed by stringified id. */
      const issuerMap = new Map<string, IInviteIssuer>();

      if (isSuperAdmin) {
         const uniqueIssuerIds = [
            ...new Map(
               validatedInvites.map(inv => [
                  inv.issuedBy.toHexString(),
                  inv.issuedBy,
               ])
            ).values(),
         ];

         const issuers = await userCollection
            .find<IInviteIssuer>(
               {
                  _id: { $in: uniqueIssuerIds },
               } satisfies StrictMongoFilter<IUserDocument>,
               {
                  projection: { _id: 1, firstName: 1, lastName: 1 },
               } satisfies StrictFindOptions<IInviteIssuer> // projection: only what we need
            )
            .toArray();

         for (const issuer of issuers) {
            issuerMap.set(issuer._id.toString(), {
               _id: issuer._id,
               firstName: issuer.firstName,
               lastName: issuer.lastName,
            });
         }
      }

      // ── Assemble the response ──────────────────────────────────────────────────
      /* Each invite is mapped to its appropriate shape based on status. The discriminated union ensures TypeScript enforces the correct fields for each branch. It's impossible to forget firstName on an accepted invite, for instance, without the compiler complaining. */
      const result: IInviteListItem[] = [];

      for (const validatedInvite of validatedInvites) {
         const _id = validatedInvite._id;
         const issuerInfo = isSuperAdmin
            ? issuerMap.get(validatedInvite.issuedBy.toString())
            : undefined;

         const base: BaseInviteItem = {
            _id,
            email: validatedInvite.email,
            role: validatedInvite.role,
            canIssueInvites: validatedInvite.canIssueInvites,
            ...(issuerInfo !== undefined && issuerInfo),
         };

         if (validatedInvite.usedAt !== null) {
            // Accepted invite: enrich with the invitee's registered name.
            const invitee = acceptedUsersMap.get(validatedInvite.email);

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
      return void res.status(200).json({ success: true, invites: result });
   } catch (err) {
      next(err);
   }
}
