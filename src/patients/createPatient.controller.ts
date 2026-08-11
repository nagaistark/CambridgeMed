import { Request, NextFunction } from 'express';
import {
   getPatientCollection,
   IPatientInput,
   PatientDocumentValidator,
   type IPatientDocument,
   type IPatientInitial,
} from '@models/Patient_v3.model.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import { auditLog } from '@services/auditLog.service.ts';
import { Permissions } from '@ssot/permissions_constants.ts';
import {
   getUserCollection,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import { ROLE_DOCTOR } from '@ssot/user_roles_constants.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { buildCreatePatientResponse } from '@utils/buildResponses.ts';
import { ObjectId } from 'mongodb';
import { Either, Schema } from 'effect';

/* Declared at module level as a named constant rather than inline inside the controller. This makes the defaults visible, testable, and reusable if other controllers ever need the same baseline. */
const CLINICAL_INFO_DEFAULTS: IPatientInput['clinicalInfo'] = {
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
      ResponseWithValidatedBody<IPatientInput | IPatientInitial>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role, permissions } = res.locals.authenticatedUser;
      const body = res.locals.validatedBody;

      const clinicalInfo: IPatientInput['clinicalInfo'] =
         'clinicalInfo' in body ? body.clinicalInfo : CLINICAL_INFO_DEFAULTS;

      const userCollection = getUserCollection();
      const doctor = await userCollection.findOne(
         { _id: body.primaryDoctorId },
         {
            projection: {
               role: 1,
               isActive: 1,
            } satisfies Partial<Record<keyof IUserDocument, 1>>,
         }
      );

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

      const now = new Date();

      const payload: IPatientDocument = {
         _id: new ObjectId(),
         isActive: body.isActive,
         primaryDoctorId: body.primaryDoctorId,
         intakeInfo: body.intakeInfo,
         clinicalInfo,
         createdAt: now,
         updatedAt: now,
      };

      const decoded = Schema.decodeUnknownEither(PatientDocumentValidator)(
         payload
      );

      if (Either.isLeft(decoded)) {
         /* If this ever fires, it means a programmer error slipped past PatientInputSchema — not a client mistake. Treat it as an internal error, not a 422. */
         return next(decoded.left);
      }

      await getPatientCollection().insertOne(decoded.right);

      /* Fire-and-forget audit record. The service swallows its own errors and logs them internally, so a failed audit write does not abort the request. req.ip is always populated in production because app.set('trust proxy', 1) is set in app.ts. The '0.0.0.0' fallback only fires in edge cases during local development where the proxy header may be absent.*/
      auditLog.record({
         actorID: new ObjectId(sub),
         actorRole: role,
         action: 'CREATE',
         resourceType: 'Patient',
         resourceIDs: [payload._id],
         patientIDs: [payload._id],
         ipAddress: req.ip ?? '0.0.0.0',
         requestId,
      });

      /* Filter the response based on what the caller is permitted to read. E.g. A secretary has no READ_CLINICAL bit, so they receive only the intake portion back. A doctor gets the full document. */
      const canReadClinical = (permissions & Permissions.READ_CLINICAL) !== 0;

      return void res
         .status(201)
         .json(buildCreatePatientResponse(payload, canReadClinical));
   } catch (err) {
      next(err);
   }
}
