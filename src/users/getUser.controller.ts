import type { Request, NextFunction } from 'express';
import { getUserCollection } from '@models/User_v3.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   SAFE_USER_PROJECTION,
   PUBLIC_USER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { ObjectId } from 'mongodb';

type GetUserParams = { id: string };

export async function getUserController(
   req: Request<GetUserParams>,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { role } = res.locals.authenticatedUser;
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Invalid user ID.`,
                  requestId
               )
            );
      }

      const isSuperAdmin = role === 'superadmin';
      const userCollection = getUserCollection();

      if (isSuperAdmin) {
         const user = await userCollection.findOne(
            { _id: new ObjectId(id) },
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
         { _id: new ObjectId(id) },
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
