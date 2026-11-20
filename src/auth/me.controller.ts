import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   UserRecoveryCodesValidator,
   type IUserDocument,
   type IUserRecoveryCodes,
} from '@models/User_v3.model.ts';
import type { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { buildMeResponse } from '@utils/buildResponses.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { USER_RECOVERY_CODES_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';
import { loadSafeUser } from '@users/loadSafeUser.ts';
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

      /* Independent reads, run in parallel. The hashes are read only to be counted: the array never leaves this function. */
      const [validatedUser, emailChange, codesRaw] = await Promise.all([
         loadSafeUser(userId, '/me user'),
         loadEmailChangeStatus(userId, new Date()),
         getUserCollection().findOne<IUserRecoveryCodes>(
            { _id: userId } satisfies StrictMongoFilter<IUserDocument>,
            {
               projection: USER_RECOVERY_CODES_PROJECTION,
            } satisfies StrictFindOneOptions<IUserRecoveryCodes>
         ),
      ]);

      if (validatedUser === null || codesRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

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
