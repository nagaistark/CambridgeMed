import {
   array,
   boolean,
   forward,
   optional,
   partialCheck,
   pipe,
   regex,
   strictObject,
} from 'valibot';
import {
   baseString,
   dateInTheFutureOrOptionallyToday,
   dateInThePastOrOptionallyToday,
   idOrName,
   longString,
   nameString,
   objectIdFormatCheck,
   positiveInteger,
   validateCanadianPostalCode,
   validateDIN,
   validateDOB,
   validateExpiryDate,
   validateNANPPhoneNumber,
} from '@utils/valibotSchemaReusables.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import {
   availableLanguages,
   prefixes,
   provincesAndTerritories,
   suffixes,
   typeOfPhones,
} from '@ssot/policy_constants.ts';
import {
   alcoholUseLevels,
   bloodTypes,
   consentCollectingMethods,
   educationLevels,
   enrollmentStatuses,
   familyRelationships,
   housingSituationVariants,
   medDeliveryRoutes,
   medicationForms,
   medicationStatuses,
   medSeverityLevels,
   sexes,
   smokingStatuses,
   substanceUseLevels,
   vaccineDeliveryRoutes,
   vaccineDeliverySites,
   vaccineDoseUnits,
   vaccineForms,
} from '@ssot/patient_related_constants.ts';

export const MedicationSchema = strictObject({
   id: baseString,
   name: baseString, // Brand or Generic name
   din: baseString, // Health Canada 8-digit Drug Identification Number
   snomedCode: optional(baseString), // Standard pan-Canadian electronic health record code
   form: makePicklist(medicationForms),
   route: makePicklist(medDeliveryRoutes),
   status: makePicklist(medicationStatuses),
   instructions: optional(longString),
   notes: optional(longString),
});

const AllergySchema = strictObject({
   substance: baseString,
   reaction: longString,
   severity: makePicklist(medSeverityLevels),
   dateDiscovered: optional(dateInThePastOrOptionallyToday),
});

const ImmunizationSchema = pipe(
   strictObject({
      name: baseString,
      din: validateDIN, // Health Canada Vaccine DIN
      form: makePicklist(vaccineForms),
      manufacturer: baseString,
      lotNumber: baseString,
      route: makePicklist(vaccineDeliveryRoutes),
      site: optional(makePicklist(vaccineDeliverySites)),
      dose: strictObject({
         value: positiveInteger,
         unit: makePicklist(vaccineDoseUnits),
      }),
      dateAdministered: dateInThePastOrOptionallyToday,
      refused: boolean(),
      refusedDate: optional(dateInThePastOrOptionallyToday),
      notes: optional(longString),
   }),
   // Validate route/site coordination and forward errors to the 'site' field path
   forward(
      partialCheck(
         [['route'], ['site']],
         ({ route, site }) => {
            return route === 'intramuscular' || route === 'subcutaneous'
               ? !!site
               : !site;
         },
         `Site selection is required for intramuscular or subcutaneous routes, and must be empty for other routes (valibot).`
      ),
      ['site']
   ),

   // Validate refusal logic and forward errors to the 'refusedDate' field path
   forward(
      partialCheck(
         [['refused'], ['refusedDate']],
         ({ refused, refusedDate }) => {
            return refused ? !!refusedDate : !refusedDate;
         },
         `Refused date must be provided if and only if the vaccine was refused (valibot).`
      ),
      ['refusedDate']
   )
);

const SurgerySchema = strictObject({
   procedure: baseString,
   date: dateInThePastOrOptionallyToday,
   performedBy: idOrName,
   hospital: nameString,
   notes: optional(longString),
});

const ConsentSchema = pipe(
   strictObject({
      type: baseString,
      granted: boolean(),
      date: optional(dateInThePastOrOptionallyToday),
      method: optional(makePicklist(consentCollectingMethods)),
      recordedBy: optional(objectIdFormatCheck),
   }),

   forward(
      partialCheck(
         [['granted'], ['date'], ['method'], ['recordedBy']],
         ({ granted, date, method, recordedBy }) => {
            return granted
               ? !!date && !!method && !!recordedBy
               : !date && !method && !recordedBy;
         },
         `When consent is granted, date, method, and the recording staff member are all required. If not granted, they must be empty (valibot).`
      ),
      ['granted']
   )
);

export const PatientSchema = strictObject({
   isActive: boolean(),
   primaryDoctorId: objectIdFormatCheck,

   intakeInfo: strictObject({
      coreIdentifiers: strictObject({
         healthCardNumber: baseString,
         healthCardVersion: baseString,
         healthCardProvince: makePicklist(provincesAndTerritories),
         healthCardExpiryDate: validateExpiryDate,
         chartNumber: pipe(
            baseString,
            regex(
               /^[A-Za-z0-9-]{10}$/,
               `Must be 10 letters, numbers, or hyphens (valibot).`
            )
         ),
         internalProviderId: optional(idOrName),
         externalProviderId: optional(baseString),
         enrolledStatus: optional(makePicklist(enrollmentStatuses)),
         enrollmentDate: optional(dateInThePastOrOptionallyToday),
         enrollmentTerminationDate: optional(dateInTheFutureOrOptionallyToday),
         enrollmentTerminationReason: optional(baseString),
      }),

      supplementalInsurance: strictObject({
         provider: baseString,
         policyNumber: baseString,
         groupNumber: optional(baseString),
         expiryDate: optional(validateExpiryDate),
      }),

      preferences: strictObject({
         preferredLanguage: makePicklist(availableLanguages),
         interpreterNeeded: optional(boolean()),
      }),

      demographics: strictObject({
         prefix: optional(makePicklist(prefixes)),
         firstName: nameString,
         lastName: nameString,
         suffix: optional(makePicklist(suffixes)),
         dateOfBirth: validateDOB,
         deceased: boolean(),
         dateOfDeath: optional(dateInThePastOrOptionallyToday),
         sexAtBirth: makePicklist(sexes),
         currentSex: makePicklist(sexes),
      }),

      socialHistory: strictObject({
         occupation: baseString,
         education: makePicklist(educationLevels),
         housingSituation: makePicklist(housingSituationVariants),
         smokingStatus: makePicklist(smokingStatuses),
         alcoholUse: makePicklist(alcoholUseLevels),
         substanceUse: makePicklist(substanceUseLevels),
      }),

      familyHistory: optional(
         array(
            strictObject({
               relationship: makePicklist(familyRelationships),
               condition: baseString,
               ageAtDiagnosis: optional(dateInThePastOrOptionallyToday),
               deceased: boolean(),
               notes: optional(longString),
            })
         )
      ),

      accessibilityNeeds: optional(
         strictObject({
            mobilityAssistance: optional(boolean()),
            wheelchairAccess: optional(boolean()),
            hearingImpairment: optional(boolean()),
            visualImpairment: optional(boolean()),
            notes: optional(longString),
         })
      ),

      contactInformation: strictObject({
         addresses: array(
            strictObject({
               street: baseString,
               city: nameString,
               province: makePicklist(provincesAndTerritories),
               postalCode: validateCanadianPostalCode,
               country: makePicklist(['Canada', 'United States']),
               isPrimary: boolean(),
            })
         ),
         phones: array(
            strictObject({
               type: makePicklist(typeOfPhones),
               number: validateNANPPhoneNumber,
               isPrimary: boolean(),
            })
         ),
      }),

      emergencyContacts: array(
         strictObject({
            name: nameString,
            relationship: makePicklist(familyRelationships),
            phone: validateNANPPhoneNumber,
         })
      ),

      nextOfKin: optional(
         strictObject({
            name: nameString,
            relationship: makePicklist(familyRelationships),
            phone: validateNANPPhoneNumber,
         })
      ),
   }),

   clinicalInfo: strictObject({
      bloodType: makePicklist(bloodTypes),
      activeMedications: array(MedicationSchema),
      allergies: array(AllergySchema),
      immunizations: array(ImmunizationSchema),
      surgicalHistory: array(SurgerySchema),
      consents: array(ConsentSchema),
   }),
});
