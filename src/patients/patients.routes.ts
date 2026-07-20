import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { requirePermissions } from '@middleware/requirePermission.ts';
import { selectPatientCreateSchema } from '@middleware/selectPatientCreateSchema.ts';
import { createPatientController } from '@patients/createPatient.controller.ts';
import { validateQuery } from '@middleware/validateQuery.ts';
import { validateParams } from '@middleware/validateParams.ts';
import { PatientQuerySchema } from '@models/Patient_v3.model.ts';
import { MongoIdParamsSchema } from '@utils/effectSchemaReusables.ts';
import { getPatientController } from '@patients/getPatient.controller.ts';
import { listPatientsController } from '@patients/listPatients.controller.ts';

const patientRouter = Router();

patientRouter.post(
   '/',
   authenticate,
   requirePermissions('WRITE_INTAKE'),
   selectPatientCreateSchema, // includes `validateBody` (!)
   createPatientController
);

/* Both GET routes share the same minimum permission: READ_INTAKE. Whether the caller also has READ_CLINICAL is a question for the controller to answer at runtime, not for the middleware gate to preemptively decide. */
patientRouter.get(
   '/',
   authenticate,
   requirePermissions('READ_INTAKE'),
   validateQuery(PatientQuerySchema),
   listPatientsController
);

patientRouter.get(
   '/:id',
   authenticate,
   requirePermissions('READ_INTAKE'),
   validateParams(MongoIdParamsSchema),
   getPatientController
);

export default patientRouter;
