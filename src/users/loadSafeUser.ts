import type { ObjectId } from 'mongodb';
import {
   getUserCollection,
   SafeUserValidator,
   type ISafeUser,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import { SAFE_USER_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { decodeStored } from '@utils/decodeStored.ts';

/* The single definition of "the user, as their own client sees them". /me, login and TOTP login all go through here, so the three can never disagree about the shape. Read-only: safe to call before any commit point. `context` names the caller in StoredDataError messages. */
export async function loadSafeUser(
   userId: ObjectId,
   context: string
): Promise<ISafeUser | null> {
   const userRaw = await getUserCollection().findOne<ISafeUser>(
      { _id: userId } satisfies StrictMongoFilter<IUserDocument>,
      {
         projection: SAFE_USER_PROJECTION,
      } satisfies StrictFindOneOptions<ISafeUser>
   );

   if (userRaw === null) return null;

   return decodeStored(SafeUserValidator, userRaw, context);
}
