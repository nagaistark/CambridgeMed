import { Request, NextFunction } from 'express';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { validateBody } from '@middleware/validateBody.ts';
import {
   patientVSchemaFull,
   patientVSchemaInitial,
} from '@models/Patient.model.ts';
import { ROLE_DOCTOR } from '@ssot/user_roles_constants.ts';

export function selectPatientCreateSchema(
   req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): void {
   const user = res.locals.authenticatedUser;

   /* Picking the schema based on what the authenticated role is allowed to submit. */
   const schema =
      user.role === ROLE_DOCTOR ? patientVSchemaFull : patientVSchemaInitial;

   /* validateBody(schema) produces a middleware function. We call that function immediately, passing the current req/res/next through. */
   validateBody(schema)(req, res, next);
}
