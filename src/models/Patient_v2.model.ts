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
import {
   availableLanguages,
   prefixes,
   provincesAndTerritories,
   suffixes,
   typeOfPhones,
} from '@ssot/policy_constants.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   baseString,
   jsDateInTheFuture,
   jsDateInThePast,
   longString,
   nameString,
   objectIdInstance,
   positiveIntegerDocument,
   validateCanadianPostalCode,
   validateDIN,
   validateNANPPhoneNumber,
} from '@utils/valibotSchemaReusables.ts';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';
import {
   array,
   boolean,
   check,
   forward,
   InferOutput,
   optional,
   pipe,
   regex,
   strictObject,
} from 'valibot';

export const PatientDocumentVSchema = strictObject({
   isActive: boolean(),
   primaryDoctorId: objectIdInstance,

   intakeInfo: strictObject({
      coreIdentifiers: pipe(
         strictObject({
            healthCardNumber: baseString,
            healthCardVersion: baseString,
            healthCardProvince: makePicklist(provincesAndTerritories),
            healthCardExpiryDate: jsDateInTheFuture,
            chartNumber: pipe(
               baseString,
               regex(
                  /^[A-Za-z0-9-]{10}$/,
                  `Must be 10 letters, numbers, or hyphens (valibot).`
               )
            ),
            internalProviderId: optional(objectIdInstance),
            externalProviderId: optional(baseString),
            enrolledStatus: optional(makePicklist(enrollmentStatuses)),
            enrollmentDate: optional(jsDateInThePast),
            enrollmentTerminationDate: optional(jsDateInTheFuture),
            enrollmentTerminationReason: optional(baseString),
         }),
         forward(
            check(({ enrolledStatus, enrollmentDate }) => {
               if (enrolledStatus === 'enrolled') {
                  return !!enrollmentDate;
               }
               return true;
            }, `Enrollment date is required when the patient status is "Enrolled".`),
            ['enrollmentDate']
         ),
         forward(
            check(
               ({
                  enrolledStatus,
                  enrollmentTerminationDate,
                  enrollmentTerminationReason,
               }) => {
                  if (enrolledStatus === 'inactive') {
                     return (
                        !!enrollmentTerminationDate &&
                        !!enrollmentTerminationReason
                     );
                  }
                  return true;
               },
               `Enrollment Termination Date are Reason are required when the patient status is "Inactive".`
            ),
            ['enrollmentTerminationDate']
         )
      ),

      supplementalInsurance: strictObject({
         provider: baseString,
         policyNumber: baseString,
         groupNumber: optional(baseString),
         expiryDate: jsDateInTheFuture,
      }),

      preferences: optional(
         strictObject({
            preferredLanguage: makePicklist(availableLanguages),
            interpreterNeeded: optional(boolean()),
         })
      ),

      demographics: pipe(
         strictObject({
            prefix: optional(makePicklist(prefixes)),
            firstName: nameString,
            lastName: nameString,
            suffix: optional(makePicklist(suffixes)),
            dateOfBirth: jsDateInThePast,
            deceased: boolean(),
            dateOfDeath: optional(jsDateInThePast),
            sexAtBirth: makePicklist(sexes),
            currentSex: makePicklist(sexes),
         }),
         forward(
            check(({ deceased, dateOfDeath }) => {
               if (deceased) {
                  return !!dateOfDeath;
               } else return !dateOfDeath;
            }, `Date of death is required if the patient is deceased.`),
            ['dateOfDeath']
         )
      ),

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
               ageAtDiagnosed: optional(positiveIntegerDocument),
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
            pipe(
               strictObject({
                  street: baseString,
                  city: nameString,
                  province: makePicklist(provincesAndTerritories),
                  postalCode: validateCanadianPostalCode,
                  country: makePicklist(['Canada', 'United States']),
                  isPrimary: boolean(),
               }),
               forward(
                  check(({ country, province }) => {
                     return country === 'Canada'
                        ? province !== 'Outside'
                        : province === 'Outside';
                  }, `Invalid province for selected country (valibot).`),
                  ['province']
               )
            )
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

      activeMedications: array(
         strictObject({
            id: baseString,
            name: baseString, // Brand or Generic name
            din: validateDIN, // Health Canada 8-digit Drug Identification Number
            snomedCode: optional(baseString), // Standard pan-Canadian electronic health record code
            form: makePicklist(medicationForms),
            route: makePicklist(medDeliveryRoutes),
            status: makePicklist(medicationStatuses),
            instructions: optional(longString),
            notes: optional(longString),
         })
      ),

      allergies: array(
         strictObject({
            substance: baseString,
            reaction: longString,
            severity: makePicklist(medSeverityLevels),
            dateDiscovered: optional(jsDateInThePast),
         })
      ),

      immunizations: array(
         pipe(
            strictObject({
               name: baseString,
               din: validateDIN, // Health Canada Vaccine DIN
               form: makePicklist(vaccineForms),
               manufacturer: baseString,
               lotNumber: baseString,
               route: makePicklist(vaccineDeliveryRoutes),
               site: optional(makePicklist(vaccineDeliverySites)),
               dose: strictObject({
                  value: positiveIntegerDocument,
                  unit: makePicklist(vaccineDoseUnits),
               }),
               dateAdministered: jsDateInThePast,
               refused: boolean(),
               refusedDate: optional(jsDateInThePast),
               notes: optional(longString),
            }),

            // Validate route/site coordination and forward errors to the 'site' field path
            forward(
               check(({ route, site }) => {
                  return route === 'intramuscular' || route === 'subcutaneous'
                     ? !!site
                     : !site;
               }, `Site selection is required for intramuscular or subcutaneous routes, and must be empty for other routes (valibot).`),
               ['site']
            ),

            // Validate refusal logic and forward errors to the 'refusedDate' field path
            forward(
               check(({ refused, refusedDate }) => {
                  return refused ? !!refusedDate : !refusedDate;
               }, `Refused date must be provided if and only if the vaccine was refused (valibot).`),
               ['refusedDate']
            )
         )
      ),

      surgicalHistory: array(
         strictObject({
            procedure: baseString,
            date: jsDateInThePast,
            performedBy: nameString,
            hospital: nameString,
            notes: optional(longString),
         })
      ),

      consents: array(
         pipe(
            strictObject({
               type: baseString,
               granted: boolean(),
               date: optional(jsDateInThePast),
               method: optional(makePicklist(consentCollectingMethods)),
               recordedBy: optional(objectIdInstance),
            }),

            forward(
               check(({ granted, date, method, recordedBy }) => {
                  return granted
                     ? !!date && !!method && !!recordedBy
                     : !date && !method && !recordedBy;
               }, `When consent is granted, date, method, and the recording staff member are all required. If not granted, they must be empty (valibot).`),
               ['granted']
            )
         )
      ),
   }),
});

export type IPatientDocument = InferOutput<typeof PatientDocumentVSchema>;

export function getPatientCollection(): Collection<IPatientDocument> {
   return DatabaseManager.getInstance()
      .clinic.db()
      .collection<IPatientDocument>('patients');
}

export const patientIndexes = [
   {
      key: {
         'intakeInfo.demographics.firstName': 1,
         'intakeInfo.demographics.lastName': 1,
      },
   },
   {
      key: {
         'intakeInfo.coreIdentifiers.healthCardNumber': 1,
         'intakeInfo.contactInformation.phones.number': 1,
      },
      unique: true,
   },
   {
      key: {
         'intakeInfo.demographics.lastName': 'text',
         'intakeInfo.demographics.firstName': 'text',
         'intakeInfo.coreIdentifiers.healthCardNumber': 'text',
         'intakeInfo.coreIdentifiers.chartNumber': 'text',
      },
   },
] satisfies readonly TypedIndexDescription<IPatientDocument>[];
