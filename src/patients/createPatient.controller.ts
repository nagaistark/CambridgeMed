import { Request, Response, NextFunction } from 'express';

import {
   IPatientDefinitionFull,
   IPatientDefinitionInit,
} from '@models/Patient.model.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';

type FullBody = IPatientDefinitionFull;
type InitBody = IPatientDefinitionInit;

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
      const user = res.locals.authenticatedUser;

      const body = res.locals['validatedBody'];
   } catch (err) {
      next(err);
   }
}
