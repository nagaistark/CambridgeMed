import {
   medDoseUnits,
   medFrequencies,
   medicationStatuses,
} from '@ssot/patient_related_constants.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import {
   baseString,
   stringDateInThePastOrOptionallyToday,
   idOrName,
   objectIdStringCheck,
   positiveIntegerInputString,
} from '@utils/valibotSchemaReusables.ts';
import { optional, strictObject } from 'valibot';
import { medicationVSchema } from '@models/Patient.model.ts';

export const PrescriptionSchema = strictObject({
   patientId: objectIdStringCheck,
   medication: medicationVSchema,
   dose: strictObject({
      value: positiveIntegerInputString,
      unit: makePicklist(medDoseUnits),
   }),
   frequency: makePicklist(medFrequencies),
   startDate: stringDateInThePastOrOptionallyToday,
   endDate: optional(stringDateInThePastOrOptionallyToday),
   status: makePicklist(medicationStatuses),
   instructions: optional(baseString),
   prescribedBy: idOrName,
   notes: optional(baseString),
});
