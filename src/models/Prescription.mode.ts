import {
   medDoseUnits,
   medFrequencies,
   medicationStatuses,
} from '@ssot/patient_related_constants.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import {
   baseString,
   dateInThePastOrOptionallyToday,
   idOrName,
   objectIdFormatCheck,
   positiveInteger,
} from '@utils/valibotSchemaReusables.ts';
import { optional, strictObject } from 'valibot';
import { medicationVSchema } from '@models/Patient.model.ts';

export const PrescriptionSchema = strictObject({
   patientId: objectIdFormatCheck,
   medication: medicationVSchema,
   dose: strictObject({
      value: positiveInteger,
      unit: makePicklist(medDoseUnits),
   }),
   frequency: makePicklist(medFrequencies),
   startDate: dateInThePastOrOptionallyToday,
   endDate: optional(dateInThePastOrOptionallyToday),
   status: makePicklist(medicationStatuses),
   instructions: optional(baseString),
   prescribedBy: idOrName,
   notes: optional(baseString),
});
