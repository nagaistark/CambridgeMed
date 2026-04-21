import type { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import {
   getUserModel,
   type SafeUser,
   type PublicUser,
} from '@models/User.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   SAFE_USER_PROJECTION,
   PUBLIC_USER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';

type GetUserParams = { id: string };

export async function getUserController(
   req: Request<GetUserParams>,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { role } = res.locals.authenticatedUser!;
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Invalid user ID.`,
                  undefined,
                  requestId
               )
            );
      }

      const isSuperAdmin = role === 'superadmin';
      const User = getUserModel();

      if (isSuperAdmin) {
         const user = (await User.findById(
            id,
            SAFE_USER_PROJECTION
         ).lean()) as SafeUser | null;
         if (!user) {
            return void res
               .status(404)
               .json(
                  createErrorResponse(
                     'NOT_FOUND',
                     `User not found.`,
                     undefined,
                     requestId
                  )
               );
         }
         return void res.status(200).json({ success: true, user });
      }

      const user = (await User.findById(
         id,
         PUBLIC_USER_PROJECTION
      ).lean()) as PublicUser | null;
      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `User not found.`,
                  undefined,
                  requestId
               )
            );
      }
      return void res.status(200).json({ success: true, user });
   } catch (err) {
      next(err);
   }
}
