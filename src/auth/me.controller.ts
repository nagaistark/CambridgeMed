import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   SafeUserValidator,
   type IUserDocument,
   type ISafeUser,
   type IUserRecoveryCodes,
   UserRecoveryCodesValidator,
} from '@models/User_v3.model.ts';
import type { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { buildMeResponse } from '@utils/buildResponses.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import {
   SAFE_USER_PROJECTION,
   USER_RECOVERY_CODES_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';
import { decodeStored } from '@utils/decodeStored.ts';

export async function meController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { userId, idleExpiresAt, absoluteExpiresAt } =
         res.locals.authenticatedUser;

      /* Independent reads, run in parallel. */
      const [userRaw, emailChange, codesRaw] = await Promise.all([
         getUserCollection().findOne<ISafeUser>(
            { _id: userId } satisfies StrictMongoFilter<IUserDocument>,
            {
               projection: SAFE_USER_PROJECTION,
            } satisfies StrictFindOneOptions<ISafeUser>
         ),
         loadEmailChangeStatus(userId, new Date()),
         getUserCollection().findOne<IUserRecoveryCodes>(
            { _id: userId } satisfies StrictMongoFilter<IUserDocument>,
            {
               projection: USER_RECOVERY_CODES_PROJECTION,
            } satisfies StrictFindOneOptions<IUserRecoveryCodes>
         ),
      ]);

      if (userRaw === null || codesRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      const validatedUser = decodeStored(
         SafeUserValidator,
         userRaw,
         '/me user'
      );
      const validatedCodes = decodeStored(
         UserRecoveryCodesValidator,
         codesRaw,
         '/me recovery codes'
      );

      return void res.status(200).json(
         buildMeResponse('Session valid.', validatedUser, emailChange, {
            session: { idleExpiresAt, absoluteExpiresAt },
            remainingRecoveryCodes: validatedUser.isTotpEnabled
               ? validatedCodes.totpRecoveryCodes.length
               : null,
         })
      );
   } catch (err) {
      next(err);
   }
}
