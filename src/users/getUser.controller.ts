import type { Request, NextFunction } from 'express';
import { getUserCollection } from '@models/User_v3.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   SAFE_USER_PROJECTION,
   PUBLIC_USER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import { IMongoIdParam } from '@utils/effectSchemaReusables.ts';

export async function getUserController(
   _req: Request,
   res: AuthenticatedResponse & ResponseWithValidatedParams<IMongoIdParam>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { role } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;

      const isSuperAdmin = role === 'superadmin';
      const userCollection = getUserCollection();

      if (isSuperAdmin) {
         const user = await userCollection.findOne(
            { _id: id },
            { projection: SAFE_USER_PROJECTION }
         );
         if (!user) {
            return void res
               .status(404)
               .json(
                  createErrorResponse('NOT_FOUND', `User not found.`, requestId)
               );
         }
         return void res.status(200).json({ success: true, user });
      }

      const user = await userCollection.findOne(
         { _id: id },
         { projection: PUBLIC_USER_PROJECTION }
      );
      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `User not found.`, requestId)
            );
      }
      return void res.status(200).json({ success: true, user });
   } catch (err) {
      next(err);
   }
}
