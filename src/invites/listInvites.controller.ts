import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import {
   getInviteCollection,
   type IInviteDoc,
} from '@models/Invite_v3.model.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { ObjectId } from 'mongodb';

type IInviteIssuer = Pick<IUserDocument, '_id' | 'firstName' | 'lastName'>;
type IPendingInviteItem = Pick<
   IInviteDoc,
   '_id' | 'email' | 'role' | 'canIssueInvites' | 'expiresAt'
> & {
   status: 'pending';
   issuedBy?: IInviteIssuer;
};

type IAcceptedInviteItem = Pick<
   IInviteDoc,
   '_id' | 'email' | 'role' | 'canIssueInvites'
> &
   Pick<IUserDocument, 'firstName' | 'lastName'> & {
      status: 'accepted';
      usedAt: Date; // narrowed from Date | null. Accepted means usedAt is guaranteed non-null.
      issuedBy?: IInviteIssuer;
   };

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
      };

      /* Non-superadmin users only see invites they personally issued. The superadmin sees everything, so no issuedBy constraint is added. */
      const ownershipFilter = isSuperAdmin
         ? {}
         : { issuedBy: new ObjectId(sub) };

      const invites = await inviteCollection
         .find({
            ...statusFilter,
            ...ownershipFilter,
         })
         .toArray();

      if (invites.length === 0) {
         return void res.status(200).json({
            success: true,
            invites: [],
         });
      }

      // ── Batch-fetch accepted invitees ──────────────────────────────────────────
      /* We collect all relevant emails and fetch matching users in one query. We then build an in-memory map for O(1) lookup during response assembly. */
      const acceptedEmails = invites
         .filter(inv => inv.usedAt !== null)
         .map(inv => inv.email);

      const acceptedUsersMap = new Map<
         string,
         { firstName: string; lastName: string }
      >();

      if (acceptedEmails.length > 0) {
         const acceptedUsers = await userCollection
            .find(
               { email: { $in: acceptedEmails } },
               { projection: { email: 1, firstName: 1, lastName: 1 } } // projection: fetch only what we need
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
               invites.map(inv => [inv.issuedBy.toHexString(), inv.issuedBy])
            ).values(),
         ];

         const issuers = await userCollection
            .find(
               { _id: { $in: uniqueIssuerIds } },
               { projection: { firstName: 1, lastName: 1 } } // projection: only what we need
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

      for (const invite of invites) {
         const _id = invite._id;
         const issuedBy = isSuperAdmin
            ? issuerMap.get(invite.issuedBy.toString())
            : undefined;

         const base = {
            _id,
            email: invite.email,
            role: invite.role,
            canIssueInvites: invite.canIssueInvites,
            ...(issuedBy !== undefined && { issuedBy }),
         };

         if (invite.usedAt !== null) {
            // Accepted invite: enrich with the invitee's registered name.
            const invitee = acceptedUsersMap.get(invite.email);

            /* This should never be null — an accepted invite implies a User document exists. If it isn't found, we fall back to empty strings rather than throwing, since this is a list endpoint and one missing user shouldn't collapse the entire response. */
            const firstName = invitee?.firstName ?? '';
            const lastName = invitee?.lastName ?? '';

            result.push({
               ...base,
               status: 'accepted',
               firstName,
               lastName,
               usedAt: invite.usedAt,
            });
         } else {
            result.push({
               ...base,
               status: 'pending',
               expiresAt: invite.expiresAt,
            });
         }
      }
      return void res.status(200).json({ success: true, invites: result });
   } catch (err) {
      next(err);
   }
}
