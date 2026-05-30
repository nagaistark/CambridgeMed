import { Request, NextFunction } from 'express';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { validateBody } from '@middleware/validateBody.ts';
import {
   patientVSchemaFull,
   patientVSchemaInitial,
} from '@models/Patient.model.ts';
import { Permissions } from '@ssot/permissions_constants.ts';

export function selectPatientCreateSchema(
   req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): void {
   const { permissions } = res.locals.authenticatedUser;

   /* Picking the schema based on what the authenticated role is allowed to submit. */
   const canWriteClinical = (permissions & Permissions.WRITE_CLINICAL) !== 0;

   const schema = canWriteClinical ? patientVSchemaFull : patientVSchemaInitial;

   /* validateBody(schema) produces a middleware function. We call that function immediately, passing the current req/res/next through. */
   validateBody(schema)(req, res, next);
}
