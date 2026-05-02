import supertest from 'supertest';
import {
   getUserModel,
   type IUserDefinition,
   type IUserDocument,
} from '@models/User.model.ts';
import { hashPassword } from '@utils/hashAndVerify.ts';
import { loginAs } from '@tests/helpers/loginAs.ts';
import {
   OptionalizeExcept,
   testDomain,
   testPassword,
   testUsername,
} from '@tests/test.utils.ts';

export type SeededUser = {
   user: IUserDocument;
   agent: supertest.Agent;
};

type SeedUserOptions = OptionalizeExcept<
   Pick<IUserDefinition, 'role' | 'canIssueInvites' | 'invitedBy'>,
   'invitedBy'
>;

function createSeedUser(username: string, domain: string) {
   let counter: number = 0;

   return async function (opts: SeedUserOptions): Promise<SeededUser> {
      const email = `${username}+invited${String(++counter).padStart(2, '0')}@${domain}`;

      const internalPassword = testPassword;
      const passwordHash = await hashPassword(internalPassword);

      const { role = 'doctor', canIssueInvites = false, invitedBy } = opts;

      const userDoc = await getUserModel().create({
         firstName: 'Test',
         lastName: `User${counter}`,
         email,
         passwordHash,
         role,
         canIssueInvites,
         invitedBy,
         isActive: true,
      });

      const agent = await loginAs({ email, password: internalPassword });

      return { user: userDoc.toObject(), agent };
   };
}

export const userFactory = createSeedUser(testUsername, testDomain);
