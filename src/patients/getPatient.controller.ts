import type { Request, NextFunction } from 'express';
import { getPatientCollection } from '@models/Patient_v3.model.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import { Permissions } from '@ssot/permissions_constants.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { buildGetPatientResponse } from '@utils/buildResponses.ts';
import { INTAKE_ONLY_PATIENT_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import { auditLog } from '@services/auditLog.service.ts';
import { ObjectId } from 'mongodb';

export async function getPatientController(
   req: Request,
   res: AuthenticatedResponse & ResponseWithValidatedParams<IMongoIdParam>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role, permissions } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;

      const canReadClinical = (permissions & Permissions.READ_CLINICAL) !== 0;

      /* Apply the exclusion projection at the database level so that clinicalInfo never crosses the wire for callers who can't read it. Filtering at the source is always preferable to filtering after the fact in application code. */
      const projection = canReadClinical ? {} : INTAKE_ONLY_PATIENT_PROJECTION;

      /* No isActive filter here — staff may legitimately need to view archived patient records (for historical reference, records requests, etc.). The isActive field is present in the response so the UI can render an "archived" indicator appropriately. */
      const patient = await getPatientCollection().findOne(
         { _id: id },
         { projection }
      );

      if (!patient) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Patient not found.`, requestId)
            );
      }

      auditLog.record({
         actorID: new ObjectId(sub),
         actorRole: role,
         action: 'READ',
         resourceType: 'Patient',
         resourceIDs: [id],
         patientIDs: [id],
         ipAddress: req.ip ?? '0.0.0.0',
         requestId,
      });

      return void res
         .status(200)
         .json(buildGetPatientResponse(patient, canReadClinical));
   } catch (err) {
      next(err);
   }
}
