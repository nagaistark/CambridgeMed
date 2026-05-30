import { Request, NextFunction } from 'express';
import {
   getPatientModel,
   IPatientDefinitionFull,
   IPatientDefinitionInit,
} from '@models/Patient.model.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import { auditLog } from '@services/auditLog.service.ts';
import { Permissions } from '@ssot/permissions_constants.ts';
import { getUserModel, IUserDocument } from '@models/User.model.ts';
import { ROLE_DOCTOR } from '@ssot/user_roles_constants.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { buildCreatePatientResponse } from '@utils/buildResponses.ts';

/* Declared at module level as a named constant rather than inline inside the controller. This makes the defaults visible, testable, and reusable if other controllers ever need the same baseline. */
const CLINICAL_INFO_DEFAULTS: IPatientDefinitionFull['clinicalInfo'] = {
   bloodType: 'unknown',
   activeMedications: [],
   allergies: [],
   immunizations: [],
   surgicalHistory: [],
   consents: [],
};

export async function createPatientController(
   req: Request,
   res: AuthenticatedResponse &
      ResponseWithValidatedBody<
         IPatientDefinitionFull | IPatientDefinitionInit
      >,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role, permissions } = res.locals.authenticatedUser;
      const body = res.locals.validatedBody;

      const clinicalInfo: IPatientDefinitionFull['clinicalInfo'] =
         'clinicalInfo' in body ? body.clinicalInfo : CLINICAL_INFO_DEFAULTS;

      const User = getUserModel();
      const doctor = await User.findById(body.primaryDoctorId, {
         role: 1,
         isActive: 1,
      } satisfies Partial<Record<keyof IUserDocument, 1>>).lean();

      if (!doctor || doctor.role !== ROLE_DOCTOR || !doctor.isActive) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `The specified primary doctor does not exist or is not an active doctor.`,
                  requestId
               )
            );
      }

      const documentToCreate: IPatientDefinitionFull = {
         isActive: body.isActive,
         primaryDoctorId: body.primaryDoctorId,
         intakeInfo: body.intakeInfo,
         clinicalInfo,
      };

      const newPatient = await getPatientModel().create(documentToCreate);

      /* We use toObject() to strip Mongoose-specific internals (like __v and the prototype chain) before sending the plain object over the wire. */
      const patientPlain = newPatient.toObject();

      /* Fire-and-forget audit record. The service swallows its own errors and logs them internally, so a failed audit write does not abort the request. req.ip is always populated in production because app.set('trust proxy', 1) is set in app.ts. The '0.0.0.0' fallback only fires in edge cases during local development where the proxy header may be absent.*/
      auditLog.record({
         actorID: sub,
         actorRole: role,
         action: 'CREATE',
         resourceType: 'Patient',
         resourceID: newPatient._id.toString(),
         patientID: newPatient._id.toString(),
         ipAddress: req.ip ?? '0.0.0.0',
         requestId,
      });

      /* Filter the response based on what the caller is permitted to read. E.g. A secretary has no READ_CLINICAL bit, so they receive only the intake portion back. A doctor gets the full document. */
      const canReadClinical = (permissions & Permissions.READ_CLINICAL) !== 0;

      return void res
         .status(201)
         .json(buildCreatePatientResponse(patientPlain, canReadClinical));
   } catch (err) {
      next(err);
   }
}
