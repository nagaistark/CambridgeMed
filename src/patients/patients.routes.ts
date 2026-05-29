import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { requirePermissions } from '@middleware/requirePermission.ts';
import { Permissions } from '@ssot/permissions_constants.ts';
import { selectPatientCreateSchema } from '@middleware/selectPatientCreateSchema.ts';

const patientRouter = Router();

patientRouter.post(
   '/',
   authenticate,
   requirePermissions(Permissions.WRITE_INTAKE),
   selectPatientCreateSchema
   // createPatientController
);
