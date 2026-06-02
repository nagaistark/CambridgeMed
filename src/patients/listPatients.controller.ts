// src/patients/listPatients.controller.ts
import type { Request, NextFunction } from 'express';
import { getPatientModel, type PatientSummary } from '@models/Patient.model.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedQuery,
} from '@utils/customTypedResponses.ts';
import { buildListPatientsResponse } from '@utils/buildResponses.ts';
import {
   LIST_PATIENT_PROJECTION,
   PATIENT_LIST_SEARCH_FIELDS,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import type { ListPatientsQuery } from '@models/Patient.model.ts';
import { escapeRegex } from '@utils/escapeRegex.ts';

type PatientListFilter = {
   isActive?: boolean;
   $or?: Array<
      Partial<Record<(typeof PATIENT_LIST_SEARCH_FIELDS)[number], RegExp>>
   >;
};

export async function listPatientsController(
   _req: Request,
   res: AuthenticatedResponse & ResponseWithValidatedQuery<ListPatientsQuery>,
   next: NextFunction
): Promise<void> {
   try {
      const { page, limit, search, includeArchived } =
         res.locals.validatedQuery;
      const skip = (page - 1) * limit;

      /* Build the filter with explicit property assignments so TypeScript verifies each one against PatientListFilter. The RegExp is compiled once and reused across all $or clauses rather than being reconstructed inside the map callback. */
      const searchPattern = search
         ? new RegExp(escapeRegex(search), 'i')
         : null;

      const filter: PatientListFilter = {};
      if (!includeArchived) filter.isActive = true;
      if (searchPattern !== null) {
         filter.$or = PATIENT_LIST_SEARCH_FIELDS.map(field => ({
            [field]: searchPattern,
         }));
      }

      const [total, patients] = await Promise.all([
         getPatientModel().countDocuments(filter),
         getPatientModel()
            .find(filter, LIST_PATIENT_PROJECTION)
            .sort({
               'intakeInfo.demographics.lastName': 1,
               'intakeInfo.demographics.firstName': 1,
            } satisfies Partial<
               Record<keyof typeof LIST_PATIENT_PROJECTION, 1 | -1>
            >)
            .skip(skip)
            .limit(limit)
            .lean<PatientSummary[]>(),
      ]);

      return void res
         .status(200)
         .json(buildListPatientsResponse(patients, total, page, limit));
   } catch (err) {
      next(err);
   }
}
