import { Request, NextFunction } from 'express';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { validateBody } from '@middleware/validateBody.ts';
import {
   PatientInputSchema,
   PatientInitialSchema,
} from '@models/Patient_v3.model.ts';
import { Permissions } from '@ssot/permissions_constants.ts';

export function selectPatientCreateSchema(
   req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): void {
   const { permissions } = res.locals.authenticatedUser;

   /* Picking the schema based on what the authenticated role is allowed to submit. */
   const canWriteClinical = (permissions & Permissions.WRITE_CLINICAL) !== 0;

   if (canWriteClinical) {
      validateBody(PatientInputSchema)(req, res, next);
   } else {
      validateBody(PatientInitialSchema)(req, res, next);
   }
}
