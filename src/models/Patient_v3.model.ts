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
   availableCountries,
   availableLanguages,
   prefixes,
   provincesAndTerritories,
   suffixes,
   typeOfPhones,
} from '@ssot/policy_constants.ts';
import {
   baseString,
   chartNumber,
   DIN,
   fullDateInThePast,
   longString,
   nameString,
   phoneNumberNANP,
   positiveIntegerStringToNumber,
   postalCodeCanada,
   shortDateInTheFutureOrToday,
   shortDateInThePast,
   snomed,
   stringToObjectId,
   validateDOB,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';

export const PatientUniSchema = Schema.Struct({
   isActive: Schema.Boolean.annotations({
      message: () => `isActive Must be a boolean.`,
   }),
   primaryDoctorId: stringToObjectId,
   intakeInfo: Schema.Struct({
      coreIdentifiers: Schema.Struct({
         healthCardNumber: baseString,
         healthCardVersion: baseString,
         healthCardProvince: Schema.Literal(...provincesAndTerritories),
         healthCardExpiryDate: shortDateInTheFutureOrToday,
         chartNumber: chartNumber,
         internalProviderId: Schema.optional(stringToObjectId),
         externalProviderId: Schema.optional(stringToObjectId),
         enrollementStatus: Schema.Literal(...enrollmentStatuses),
         enrollmentDate: Schema.optional(fullDateInThePast),
         enrollmentTerminationDate: Schema.optional(fullDateInThePast),
         enrollmentTerminationReason: Schema.optional(baseString),
      }).pipe(
         Schema.filter(core => {
            const issues: Array<Schema.FilterIssue> = [];

            if (core.internalProviderId && core.externalProviderId) {
               issues.push({
                  path: ['externalProviderId'],
                  message: `Cannot provide both an internal and external provider.`,
               });
            }

            if (!core.internalProviderId && !core.externalProviderId) {
               issues.push({
                  path: ['internalProviderId'],
                  message: `You must provide either an internal or external provider.`,
               });
            }

            if (core.enrollementStatus === 'enrolled' && !core.enrollmentDate) {
               issues.push({
                  path: ['enrollmentDate'],
                  message: `Enrollment date is required when the patient status is "Enrolled".`,
               });
            }

            if (
               core.enrollementStatus === 'inactive' &&
               (!core.enrollmentTerminationDate ||
                  !core.enrollmentTerminationReason)
            ) {
               issues.push({
                  path: ['enrollmentTerminationDate'],
                  message: `Enrollment Termination Date and Reason are required when the patient status is "Inactive".`,
               });
            }

            return issues;
         })
      ),

      supplementalInsurance: Schema.Struct({
         provider: baseString,
         policyNumber: baseString,
         groupNumber: Schema.optional(baseString),
         expiryDate: shortDateInTheFutureOrToday,
      }),

      preferences: Schema.Struct({
         preferredLanguage: Schema.Literal(...availableLanguages),
         interpreterNeeded: Schema.Boolean,
      }),

      demographics: Schema.Struct({
         prefix: Schema.optional(Schema.Literal(...prefixes)),
         firstName: nameString,
         lastName: nameString,
         suffix: Schema.optional(Schema.Literal(...suffixes)),
         dateOfBirth: validateDOB,
         deceased: Schema.Boolean,
         dateOfDeath: Schema.optional(shortDateInThePast),
         sexAtBirth: Schema.Literal(...sexes),
         currentSex: Schema.Literal(...sexes),
      }).pipe(
         Schema.filter(dmg => {
            const issues: Array<Schema.FilterIssue> = [];

            if (dmg.deceased && !dmg.dateOfDeath) {
               issues.push({
                  path: ['dateOfDeath'],
                  message: `Date of death is required if the patient is deceased.`,
               });
            }

            if (!dmg.deceased && dmg.dateOfDeath) {
               issues.push({
                  path: ['dateOfDeath'],
                  message: `Alive patients must not have a date of death.`,
               });
            }

            return issues;
         })
      ),

      socialHistory: Schema.Struct({
         occupation: baseString,
         education: Schema.Literal(...educationLevels),
         housingSituation: Schema.Literal(...housingSituationVariants),
         smokingStatus: Schema.Literal(...smokingStatuses),
         alcoholUse: Schema.Literal(...alcoholUseLevels),
         substanceUse: Schema.Literal(...substanceUseLevels),
      }),

      familyHistory: Schema.optional(
         Schema.Array(
            Schema.Struct({
               relationship: Schema.Literal(...familyRelationships),
               condition: baseString,
               ageAtDiagnosed: Schema.optional(positiveIntegerStringToNumber),
               deceased: Schema.Boolean,
               notes: Schema.optional(longString),
            })
         )
      ),

      accessibilityNeeds: Schema.optional(
         Schema.Struct({
            mobilityAssistance: Schema.optional(Schema.Boolean),
            wheelchairAccess: Schema.optional(Schema.Boolean),
            hearingImpairment: Schema.optional(Schema.Boolean),
            visualImpairment: Schema.optional(Schema.Boolean),
            notes: Schema.optional(longString),
         })
      ),

      contactInformation: Schema.Struct({
         addresses: Schema.Array(
            Schema.Struct({
               street: baseString,
               city: nameString,
               province: Schema.Literal(...provincesAndTerritories),
               postalCode: postalCodeCanada,
               country: Schema.Literal(...availableCountries),
               isPrimary: Schema.Boolean,
            }).pipe(
               Schema.filter(addresses => {
                  if (
                     (addresses.country === 'Canada' &&
                        addresses.province === 'Outside') ||
                     (addresses.country !== 'Canada' &&
                        addresses.province !== 'Outside')
                  ) {
                     return {
                        path: ['province'],
                        message: `Invalid province for selected country.`,
                     };
                  }
               })
            )
         ),
         phones: Schema.Array(
            Schema.Struct({
               type: Schema.Literal(...typeOfPhones),
               number: phoneNumberNANP,
               isPrimary: Schema.Boolean,
            })
         ),
      }),

      emergencyContacts: Schema.Array(
         Schema.Struct({
            name: nameString,
            relationship: Schema.Literal(...familyRelationships),
            phone: phoneNumberNANP,
         })
      ),

      nextOfKin: Schema.optional(
         Schema.Struct({
            name: nameString,
            relationship: Schema.Literal(...familyRelationships),
            phone: phoneNumberNANP,
         })
      ),
   }),

   clinicalInfo: Schema.Struct({
      bloodType: Schema.Literal(...bloodTypes),
      activeMedications: Schema.Array(
         Schema.Struct({
            id: baseString,
            name: baseString,
            din: DIN,
            snomedCode: Schema.optional(snomed),
            form: Schema.Literal(...medicationForms),
            route: Schema.Literal(...medDeliveryRoutes),
            status: Schema.Literal(...medicationStatuses),
            instructions: Schema.optional(longString),
            notes: Schema.optional(longString),
         })
      ),

      allergies: Schema.Array(
         Schema.Struct({
            substance: baseString,
            reaction: longString,
            severity: Schema.Literal(...medSeverityLevels),
            dateDiscovered: Schema.optional(shortDateInThePast),
         })
      ),

      immunizations: Schema.Array(
         Schema.Struct({
            name: baseString,
            din: DIN,
            form: Schema.Literal(...vaccineForms),
            manufacturer: baseString,
            lotNumber: baseString,
            route: Schema.Literal(...vaccineDeliveryRoutes),
            site: Schema.optional(Schema.Literal(...vaccineDeliverySites)),
            dose: Schema.Struct({
               value: positiveIntegerStringToNumber,
               unit: Schema.Literal(...vaccineDoseUnits),
            }),
            dateAdministered: fullDateInThePast,
            refused: Schema.Boolean,
            refusedDate: Schema.optional(fullDateInThePast),
            notes: Schema.optional(longString),
         }).pipe(
            Schema.filter(immunizations => {
               const issues: Array<Schema.FilterIssue> = [];

               if (
                  (immunizations.route === 'intramuscular' ||
                     immunizations.route === 'subcutaneous') &&
                  !immunizations.site
               ) {
                  issues.push({
                     path: ['site'],
                     message: `Site selection is required for intramuscular or subcutaneous routes.`,
                  });
               }

               if (
                  immunizations.route !== 'intramuscular' &&
                  immunizations.route !== 'subcutaneous' &&
                  !immunizations.site
               ) {
                  issues.push({
                     path: ['site'],
                     message: `Site selection must be empty for  routes other than intramuscular or subcutaneous.`,
                  });
               }

               if (
                  (immunizations.refused && !immunizations.refusedDate) ||
                  (!immunizations.refused && immunizations.refusedDate)
               ) {
                  issues.push({
                     path: ['refusedDate'],
                     message: `Refused date must be provided if and only if the vaccine was refused.`,
                  });
               }

               return issues;
            })
         )
      ),

      surgicalHistory: Schema.Array(
         Schema.Struct({
            procedure: baseString,
            date: fullDateInThePast,
            performedBy: nameString,
            hospital: nameString,
            notes: Schema.optional(longString),
         })
      ),

      consents: Schema.Array(
         Schema.Struct({
            type: baseString,
            granted: Schema.Boolean,
            date: Schema.optional(fullDateInThePast),
            method: Schema.optional(
               Schema.Literal(...consentCollectingMethods)
            ),
            recordedBy: Schema.optional(stringToObjectId),
         }).pipe(
            Schema.filter(consents => {
               const issues: Array<Schema.FilterIssue> = [];

               if (
                  consents.granted &&
                  (!consents.date || !consents.method || !consents.recordedBy)
               ) {
                  issues.push({
                     path: ['granted'],
                     message: `When consent is granted, date, method, and the recording staff member are all required.`,
                  });
               }

               if (
                  !consents.granted &&
                  (consents.date || consents.method || consents.recordedBy)
               ) {
                  issues.push({
                     path: ['granted'],
                     message: `If not granted, date, method, and the recording staff member must be empty.`,
                  });
               }

               return issues;
            })
         )
      ),
   }),
});

type IPatientDoc = Schema.Schema.Type<typeof PatientUniSchema>;

export function getPatientCollection(): Collection<IPatientDoc> {
   return DatabaseManager.getInstance()
      .clinic.db()
      .collection<IPatientDoc>('patients');
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
] satisfies readonly TypedIndexDescription<IPatientDoc>[];
