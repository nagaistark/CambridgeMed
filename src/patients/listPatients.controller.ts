import type { Request, NextFunction } from 'express';
import {
   getPatientCollection,
   type ListPatientsQuery,
} from '@models/Patient_v3.model.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedQuery,
} from '@utils/customTypedResponses.ts';
import { buildCursorPatientsResponse } from '@utils/buildResponses.ts';
import { LIST_PATIENT_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import { decodeCursor } from '@utils/cursorPagination.ts';
import { auditLog } from '@services/auditLog.service.ts';
import { ObjectId } from 'mongodb';

export const PATIENT_SORT_FIELDS = [
   'intakeInfo.demographics.lastName',
   'intakeInfo.demographics.firstName',
   '_id',
] as const satisfies ReadonlyArray<keyof typeof LIST_PATIENT_PROJECTION>;

type SortFieldsTuple = typeof PATIENT_SORT_FIELDS;
type LastNameKey = SortFieldsTuple[0]; // Strictly evaluates to 'intakeInfo.demographics.lastName'
type FirstNameKey = SortFieldsTuple[1]; // Strictly evaluates to 'intakeInfo.demographics.firstName'
type IdKey = SortFieldsTuple[2]; // Strictly evaluates to '_id'

// Construct the compound cursor logic using the derived keys
type CursorSortCondition =
   | { [K in LastNameKey]: { $gt: string } }
   | ({ [K in LastNameKey]: string } & { [K in FirstNameKey]: { $gt: string } })
   | ({ [K in LastNameKey]: string } & { [K in FirstNameKey]: string } & {
        [K in IdKey]: { $gt: ObjectId };
     });

type PatientCursorFilter = {
   isActive?: boolean;
   $text?: { $search: string };
   $or?: Array<CursorSortCondition>;
};

export async function listPatientsController(
   req: Request,
   res: AuthenticatedResponse & ResponseWithValidatedQuery<ListPatientsQuery>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role } = res.locals.authenticatedUser;
      const { limit, search, includeArchived, cursor } =
         res.locals.validatedQuery;

      // 1. Initialize our typed filter layout
      const filter: PatientCursorFilter = {};

      if (!includeArchived) {
         filter.isActive = true;
      }

      if (search) {
         filter.$text = { $search: search };
      }

      if (cursor) {
         const decoded = decodeCursor(cursor); // Decodes back to [string, string, string]
         if (decoded) {
            const [cursorLastName, cursorFirstName, cursorId] = decoded;

            filter.$or = [
               { [PATIENT_SORT_FIELDS[0]]: { $gt: cursorLastName } },
               {
                  [PATIENT_SORT_FIELDS[0]]: cursorLastName,
                  [PATIENT_SORT_FIELDS[1]]: { $gt: cursorFirstName },
               },
               {
                  [PATIENT_SORT_FIELDS[0]]: cursorLastName,
                  [PATIENT_SORT_FIELDS[1]]: cursorFirstName,
                  [PATIENT_SORT_FIELDS[2]]: {
                     $gt: new ObjectId(cursorId),
                  },
               },
            ] as Array<CursorSortCondition>;
         }
      }

      // 2. Feed the configuration into Mongoose safely
      const patients = await getPatientCollection()
         .find(filter, {
            projection: LIST_PATIENT_PROJECTION,
            sort: {
               [PATIENT_SORT_FIELDS[0]]: 1,
               [PATIENT_SORT_FIELDS[1]]: 1,
               [PATIENT_SORT_FIELDS[2]]: 1,
            } satisfies Record<SortFieldsTuple[number], 1 | -1>,
            limit: limit + 1,
         })
         .toArray();

      auditLog.record({
         actorID: new ObjectId(sub),
         actorRole: role,
         action: 'READ',
         resourceType: 'Patient',
         resourceIDs: patients.map(patient => patient._id),
         patientIDs: patients.map(patient => patient._id),
         ipAddress: req.ip ?? '0.0.0.0',
         requestId,
      });

      return void res
         .status(200)
         .json(buildCursorPatientsResponse(patients, limit));
   } catch (err) {
      next(err);
   }
}
