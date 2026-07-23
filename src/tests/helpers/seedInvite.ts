import {
   getInviteCollection,
   type IInviteInput,
   type IInviteDoc,
} from '@models/Invite_v3.model.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import { Optionalize, testDomain, testUsername } from '@tests/test.utils.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import { ObjectId } from 'mongodb';

type SeedInviteOptions = Optionalize<Omit<IInviteInput, 'email'>> &
   Pick<IInviteDoc, 'issuedBy'>;

function createSeedInvite(username: string, domain: string) {
   let counter = 0;

   return async function (opts: SeedInviteOptions): Promise<IInviteDoc> {
      const email = `${username}+invited${String(++counter).padStart(2, '0')}@${domain}`;
      const tokenHash = generateStandardHash(email);
      const expiresAt = new Date(
         getMaxAgeTokens().refreshTokenExpirationTimestampMS
      );

      const { role = 'doctor', canIssueInvites = false, issuedBy } = opts;

      const now = new Date();

      const payload: IInviteDoc = {
         _id: new ObjectId(),
         tokenHash,
         usedAt: null,
         expiresAt,
         issuedBy,
         role,
         canIssueInvites,
         email,
         createdAt: now,
         updatedAt: now,
      };

      await getInviteCollection().insertOne(payload);

      return payload;
   };
}

export const inviteFactory = createSeedInvite(testUsername, testDomain);
