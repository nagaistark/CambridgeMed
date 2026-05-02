import {
   getInviteModel,
   IInviteCreateBody,
   IInviteDefinition,
   type IInviteDocument,
} from '@models/Invite.model.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import { Optionalize, testDomain, testUsername } from '@tests/test.utils.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';

type SeedInviteOptions = Optionalize<Omit<IInviteCreateBody, 'email'>> &
   Pick<IInviteDefinition, 'issuedBy'>;

function createSeedInvite(username: string, domain: string) {
   let counter = 0;

   return async function (opts: SeedInviteOptions): Promise<IInviteDocument> {
      const email = `${username}+invited${String(++counter).padStart(2, '0')}@${domain}`;
      const tokenHash = generateStandardHash(email);
      const expiresAt = new Date(getMaxAgeTokens().RTEXP);

      const { role = 'doctor', canIssueInvites = false, issuedBy } = opts;

      const invite = await getInviteModel().create({
         email,
         role,
         canIssueInvites,
         tokenHash,
         expiresAt,
         usedAt: null,
         issuedBy,
      });

      return invite.toObject();
   };
}

export const inviteFactory = createSeedInvite(testUsername, testDomain);
