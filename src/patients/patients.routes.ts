import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { requirePermissions } from '@middleware/requirePermission.ts';
import { Permissions } from '@ssot/permissions_constants.ts';
import { selectPatientCreateSchema } from '@middleware/selectPatientCreateSchema.ts';
import { createPatientController } from '@patients/createPatient.controller.ts';
import { validateQuery } from '@middleware/validateQuery.ts';
import { validateParams } from '@middleware/validateParams.ts';
import { PatientQuerySchema } from '@models/Patient.model.ts';
import { MongoIdParamSchema } from '@utils/valibotSchemaReusables.ts';
import { getPatientController } from '@patients/getPatient.controller.ts';
import { listPatientsController } from '@patients/listPatients.controller.ts';

const patientRouter = Router();

patientRouter.post(
   '/',
   authenticate,
   requirePermissions(Permissions.WRITE_INTAKE),
   selectPatientCreateSchema, // includes `validateBody` (!)
   createPatientController
);

/* Both GET routes share the same minimum permission: READ_INTAKE. Whether the caller also has READ_CLINICAL is a question for the controller to answer at runtime, not for the middleware gate to preemptively decide. */
patientRouter.get(
   '/',
   authenticate,
   requirePermissions(Permissions.READ_INTAKE),
   validateQuery(PatientQuerySchema),
   listPatientsController
);

patientRouter.get(
   '/:id',
   authenticate,
   requirePermissions(Permissions.READ_INTAKE),
   validateParams(MongoIdParamSchema),
   getPatientController
);

export default patientRouter;
