import { hashPassword } from '@utils/hashAndVerify.ts';
import { getUserModel } from '@models/User.model.ts';
import type { IUserDocument } from '@models/User.model.ts';
import { testPassword } from '@tests/test.utils.ts';

export async function seedSuperadmin(): Promise<IUserDocument> {
   const User = getUserModel();
   const passwordHash = await hashPassword(testPassword);

   const superadmin = await User.create({
      firstName: 'Super',
      lastName: 'Admin',
      email: 'jascha.stark+superadmin@gmail.com',
      passwordHash,
      role: 'superadmin',
      canIssueInvites: true,
      isActive: true,
   });

   return superadmin.toObject();
}
