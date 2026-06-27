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
import { PathMap_AllReq } from '@utils/pathFinder_v2.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   baseString,
   chartNumberValidator,
   jsDateInTheFuture,
   jsDateInThePast,
   longString,
   nameString,
   objectIdInstance,
   positiveIntegerDocument,
   positiveIntegerInput,
   stringDateInTheFutureOrOptionallyToday,
   stringDateInThePastOrOptionallyToday,
   stringToObjectId,
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
   GenericSchema,
   InferOutput,
   optional,
   pipe,
   strictObject,
} from 'valibot';

// ── The Patient model Sub-Constants ──────────────────────────────────────────────
const CoreIdentifiersDocumentVSchema = pipe(
   strictObject({
      healthCardNumber: baseString,
      healthCardVersion: baseString,
      healthCardProvince: makePicklist(provincesAndTerritories),
      healthCardExpiryDate: jsDateInTheFuture,
      chartNumber: chartNumberValidator,
      internalProviderId: optional(objectIdInstance),
      externalProviderId: optional(baseString),
      enrolledStatus: optional(makePicklist(enrollmentStatuses)),
      enrollmentDate: optional(jsDateInThePast),
      enrollmentTerminationDate: optional(jsDateInThePast),
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
                  !!enrollmentTerminationDate && !!enrollmentTerminationReason
               );
            }
            return true;
         },
         `Enrollment Termination Date and Reason are required when the patient status is "Inactive".`
      ),
      ['enrollmentTerminationDate']
   )
);

const SupplementalInsuranceDocumentVSchema = strictObject({
   provider: baseString,
   policyNumber: baseString,
   groupNumber: optional(baseString),
   expiryDate: jsDateInTheFuture,
});

const PreferencesDocumentVSchema = optional(
   strictObject({
      preferredLanguage: makePicklist(availableLanguages),
      interpreterNeeded: optional(boolean()),
   })
);

const DemographicsDocumentVSchema = pipe(
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
);

const SocialHistoryDocumentVSchema = strictObject({
   occupation: baseString,
   education: makePicklist(educationLevels),
   housingSituation: makePicklist(housingSituationVariants),
   smokingStatus: makePicklist(smokingStatuses),
   alcoholUse: makePicklist(alcoholUseLevels),
   substanceUse: makePicklist(substanceUseLevels),
});

const FamilyHistoryDocumentVSchema = optional(
   array(
      strictObject({
         relationship: makePicklist(familyRelationships),
         condition: baseString,
         ageAtDiagnosed: optional(positiveIntegerDocument),
         deceased: boolean(),
         notes: optional(longString),
      })
   )
);

const AccessibilityNeedsVSchema = optional(
   strictObject({
      mobilityAssistance: optional(boolean()),
      wheelchairAccess: optional(boolean()),
      hearingImpairment: optional(boolean()),
      visualImpairment: optional(boolean()),
      notes: optional(longString),
   })
);

const AddressesEntryVSchema = pipe(
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
);

const PhonesEntryVSchema = strictObject({
   type: makePicklist(typeOfPhones),
   number: validateNANPPhoneNumber,
   isPrimary: boolean(),
});

const ContactInformationDocumentVSchema = strictObject({
   addresses: array(AddressesEntryVSchema),
   phones: array(PhonesEntryVSchema),
});

const EmergencyContactsDocumentVSchema = array(
   strictObject({
      name: nameString,
      relationship: makePicklist(familyRelationships),
      phone: validateNANPPhoneNumber,
   })
);

const NextOfKinDocumentVSchema = optional(
   strictObject({
      name: nameString,
      relationship: makePicklist(familyRelationships),
      phone: validateNANPPhoneNumber,
   })
);

const ActiveMedicationsEntryDocumentVSchema = array(
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
);

const AllergiesEntryDocumentVSchema = array(
   strictObject({
      substance: baseString,
      reaction: longString,
      severity: makePicklist(medSeverityLevels),
      dateDiscovered: optional(jsDateInThePast),
   })
);

const immunizationDoseDocumentVSchema = array(
   strictObject({
      value: positiveIntegerDocument,
      unit: makePicklist(vaccineDoseUnits),
   })
);

const ImmunizationsEntryDocumentVSchema = array(
   pipe(
      strictObject({
         name: baseString,
         din: validateDIN, // Health Canada Vaccine DIN
         form: makePicklist(vaccineForms),
         manufacturer: baseString,
         lotNumber: baseString,
         route: makePicklist(vaccineDeliveryRoutes),
         site: optional(makePicklist(vaccineDeliverySites)),
         dose: immunizationDoseDocumentVSchema,
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
);

const SurgicalHistoryDocumentVSchema = array(
   strictObject({
      procedure: baseString,
      date: jsDateInThePast,
      performedBy: nameString,
      hospital: nameString,
      notes: optional(longString),
   })
);

const ConsentsDocumentVSchema = array(
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
);

// ── The Runtime "Document" Schema as the SSOT ────────────────────────────────────
export const PatientDocumentVSchema = strictObject({
   isActive: boolean(),
   primaryDoctorId: objectIdInstance,

   intakeInfo: strictObject({
      // Needs manual re-writing for Input
      coreIdentifiers: CoreIdentifiersDocumentVSchema,

      // Needs manual re-writing for Input
      supplementalInsurance: SupplementalInsuranceDocumentVSchema,

      // Safe for spreading
      preferences: PreferencesDocumentVSchema,

      // Needs manual re-writing for Input
      demographics: DemographicsDocumentVSchema,

      // Safe for spreading
      socialHistory: SocialHistoryDocumentVSchema,

      // Needs manual re-writing for Input
      familyHistory: FamilyHistoryDocumentVSchema,

      // Safe for spreading
      accessibilityNeeds: AccessibilityNeedsVSchema,

      // Safe for spreading
      contactInformation: ContactInformationDocumentVSchema,

      // Safe for spreading
      emergencyContacts: EmergencyContactsDocumentVSchema,

      // Safe for spreading
      nextOfKin: NextOfKinDocumentVSchema,
   }),

   clinicalInfo: strictObject({
      bloodType: makePicklist(bloodTypes),

      // Safe for spreading
      activeMedications: ActiveMedicationsEntryDocumentVSchema,

      // Needs manual re-writing for Input
      allergies: AllergiesEntryDocumentVSchema,

      // Needs manual re-writing for Input
      immunizations: ImmunizationsEntryDocumentVSchema,

      // Needs manual) re-writing for Input
      surgicalHistory: SurgicalHistoryDocumentVSchema,

      // Needs manual re-writing for Input
      consents: ConsentsDocumentVSchema,
   }),
});

// ── The Full Type Tree ───────────────────────────────────────────────────────────
export type IPatientDocument = InferOutput<typeof PatientDocumentVSchema>;

// ── The Sub-constant Paths ───────────────────────────────────────────────────────
type IIntakeInfo = IPatientDocument['intakeInfo'];
type IClinicalInfo = IPatientDocument['clinicalInfo'];

type CoreIdentifiersPaths = PathMap_AllReq<
   IIntakeInfo['coreIdentifiers'],
   GenericSchema
>;
type SupplementalInsurancePaths = PathMap_AllReq<
   IIntakeInfo['supplementalInsurance'],
   GenericSchema
>;
type PreferencesPaths = PathMap_AllReq<
   IIntakeInfo['preferences'],
   GenericSchema
>;
type DemographicsPaths = PathMap_AllReq<
   IIntakeInfo['demographics'],
   GenericSchema
>;
type SocialHistoryPaths = PathMap_AllReq<
   IIntakeInfo['socialHistory'],
   GenericSchema
>;
type FamilyHistoryEntryPaths = PathMap_AllReq<
   NonNullable<IIntakeInfo['familyHistory']>[number],
   GenericSchema
>;
type AccessibilityNeedsPaths = PathMap_AllReq<
   NonNullable<IIntakeInfo['accessibilityNeeds']>,
   GenericSchema
>;
type ContactInformationPaths = PathMap_AllReq<
   IIntakeInfo['contactInformation'],
   GenericSchema
>;
type AddressPaths = PathMap_AllReq<
   IIntakeInfo['contactInformation']['addresses'][number],
   GenericSchema
>;
type PhonesPaths = PathMap_AllReq<
   IIntakeInfo['contactInformation']['phones'][number],
   GenericSchema
>;
type EmergencyContactsEntryPaths = PathMap_AllReq<
   IIntakeInfo['emergencyContacts'][number],
   GenericSchema
>;
type NextOfKinPaths = PathMap_AllReq<
   NonNullable<IIntakeInfo['nextOfKin']>,
   GenericSchema
>;

type ActiveMedicationsEntryPaths = PathMap_AllReq<
   IClinicalInfo['activeMedications'][number],
   GenericSchema
>;
type AllergiesEntryPaths = PathMap_AllReq<
   IClinicalInfo['allergies'][number],
   GenericSchema
>;
type ImmunizationDosePaths = PathMap_AllReq<
   IClinicalInfo['immunizations'][number]['dose'],
   GenericSchema
>;
type ImmunizationsEntryPaths = PathMap_AllReq<
   IClinicalInfo['immunizations'][number],
   GenericSchema
>;
type SurgicalHistoryEntryPaths = PathMap_AllReq<
   IClinicalInfo['surgicalHistory'][number],
   GenericSchema
>;
type ConsentsEntryPaths = PathMap_AllReq<
   IClinicalInfo['consents'][number],
   GenericSchema
>;

// ── The shapes constained by the Paths ───────────────────────────────────────────
const coreIdentifiersShape = {
   healthCardNumber: baseString,
   healthCardVersion: baseString,
   healthCardProvince: makePicklist(provincesAndTerritories),
   healthCardExpiryDate: stringDateInTheFutureOrOptionallyToday,
   chartNumber: chartNumberValidator,
   internalProviderId: optional(stringToObjectId),
   externalProviderId: optional(baseString),
   enrolledStatus: optional(makePicklist(enrollmentStatuses)),
   enrollmentDate: optional(stringDateInThePastOrOptionallyToday),
   enrollmentTerminationDate: optional(stringDateInThePastOrOptionallyToday),
   enrollmentTerminationReason: optional(baseString),
} satisfies CoreIdentifiersPaths;

const supplementalInsuranceShape = {
   provider: baseString,
   policyNumber: baseString,
   groupNumber: optional(baseString),
   expiryDate: stringDateInTheFutureOrOptionallyToday,
} satisfies SupplementalInsurancePaths;

const preferencesShape = {
   preferredLanguage: makePicklist(availableLanguages),
   interpreterNeeded: optional(boolean()),
} satisfies PreferencesPaths;

const demographicsShape = {
   prefix: optional(makePicklist(prefixes)),
   firstName: nameString,
   lastName: nameString,
   suffix: optional(makePicklist(suffixes)),
   dateOfBirth: stringDateInThePastOrOptionallyToday,
   deceased: boolean(),
   dateOfDeath: optional(stringDateInThePastOrOptionallyToday),
   sexAtBirth: makePicklist(sexes),
   currentSex: makePicklist(sexes),
} satisfies DemographicsPaths;

const socialHistoryShape = {
   occupation: baseString,
   education: makePicklist(educationLevels),
   housingSituation: makePicklist(housingSituationVariants),
   smokingStatus: makePicklist(smokingStatuses),
   alcoholUse: makePicklist(alcoholUseLevels),
   substanceUse: makePicklist(substanceUseLevels),
} satisfies SocialHistoryPaths;

const familyHistoryEntryShape = {
   relationship: makePicklist(familyRelationships),
   condition: baseString,
   ageAtDiagnosed: optional(positiveIntegerInput),
   deceased: boolean(),
   notes: optional(longString),
} satisfies FamilyHistoryEntryPaths;

const accessibilityNeedsShape = {
   mobilityAssistance: optional(boolean()),
   wheelchairAccess: optional(boolean()),
   hearingImpairment: optional(boolean()),
   visualImpairment: optional(boolean()),
   notes: optional(longString),
} satisfies AccessibilityNeedsPaths;

const addressesEntryShape = {
   street: baseString,
   city: nameString,
   province: makePicklist(provincesAndTerritories),
   postalCode: validateCanadianPostalCode,
   country: makePicklist(['Canada', 'United States']),
   isPrimary: boolean(),
} satisfies AddressPaths;

const phoneEntryShape = {
   type: makePicklist(typeOfPhones),
   number: validateNANPPhoneNumber,
   isPrimary: boolean(),
} satisfies PhonesPaths;

const contactInformationShape = {
   addresses: array(
      pipe(
         strictObject({ ...addressesEntryShape }),
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
   phones: array(strictObject({ ...phoneEntryShape })),
} satisfies ContactInformationPaths;

const emergencyContactsEntryShape = {
   name: nameString,
   relationship: makePicklist(familyRelationships),
   phone: validateNANPPhoneNumber,
} satisfies EmergencyContactsEntryPaths;

const nextOfKinShape = {
   name: nameString,
   relationship: makePicklist(familyRelationships),
   phone: validateNANPPhoneNumber,
} satisfies NextOfKinPaths;

const activeMedicationsEntryShape = {
   id: baseString,
   name: baseString,
   din: validateDIN,
   snomedCode: optional(baseString),
   form: makePicklist(medicationForms),
   route: makePicklist(medDeliveryRoutes),
   status: makePicklist(medicationStatuses),
   instructions: optional(longString),
   notes: optional(longString),
} satisfies ActiveMedicationsEntryPaths;

const allergiesEntryShape = {
   substance: baseString,
   reaction: longString,
   severity: makePicklist(medSeverityLevels),
   dateDiscovered: optional(stringDateInThePastOrOptionallyToday),
} satisfies AllergiesEntryPaths;

const immunizationDoseShape = {
   value: positiveIntegerInput,
   unit: makePicklist(vaccineDoseUnits),
} satisfies ImmunizationDosePaths;

const immunizationsEntryShape = {
   name: baseString,
   din: validateDIN,
   form: makePicklist(vaccineForms),
   manufacturer: baseString,
   lotNumber: baseString,
   route: makePicklist(vaccineDeliveryRoutes),
   site: optional(makePicklist(vaccineDeliverySites)),
   dose: strictObject({ ...immunizationDoseShape }),
   dateAdministered: stringDateInThePastOrOptionallyToday,
   refused: boolean(),
   refusedDate: optional(stringDateInThePastOrOptionallyToday),
   notes: optional(longString),
} satisfies ImmunizationsEntryPaths;

const surgicalHistoryEntryShape = {
   procedure: baseString,
   date: stringDateInThePastOrOptionallyToday,
   performedBy: nameString,
   hospital: nameString,
   notes: optional(longString),
} satisfies SurgicalHistoryEntryPaths;

const consentsEntryShape = {
   type: baseString,
   granted: boolean(),
   date: optional(stringDateInThePastOrOptionallyToday),
   method: optional(makePicklist(consentCollectingMethods)),
   recordedBy: optional(stringToObjectId),
} satisfies ConsentsEntryPaths;

// ── The Runtime "Input" Schema (manually build with TS supervision) ──────────────
export const PatientInputVSchema = strictObject({
   isActive: boolean(),
   primaryDoctorId: stringToObjectId,
   intakeInfo: strictObject({
      coreIdentifiers: pipe(
         strictObject({
            ...coreIdentifiersShape,
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
               `Enrollment Termination Date and Reason are required when the patient status is "Inactive".`
            ),
            ['enrollmentTerminationDate']
         )
      ),
      supplementalInsurance: strictObject({
         ...supplementalInsuranceShape,
      }),
      preferences: optional(
         strictObject({
            ...preferencesShape,
         })
      ),
      demographics: pipe(
         strictObject({
            ...demographicsShape,
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
         ...socialHistoryShape,
      }),
      familyHistory: optional(
         array(
            strictObject({
               ...familyHistoryEntryShape,
            })
         )
      ),
      accessibilityNeeds: optional(
         strictObject({
            ...accessibilityNeedsShape,
         })
      ),
      contactInformation: strictObject({
         ...contactInformationShape,
      }),
      emergencyContacts: array(
         strictObject({
            ...emergencyContactsEntryShape,
         })
      ),
      nextOfKin: optional(
         strictObject({
            ...nextOfKinShape,
         })
      ),
   } satisfies Record<keyof IPatientDocument['intakeInfo'], GenericSchema>),

   clinicalInfo: strictObject({
      bloodType: makePicklist(bloodTypes),
      activeMedications: array(
         strictObject({
            ...activeMedicationsEntryShape,
         })
      ),
      allergies: array(
         strictObject({
            ...allergiesEntryShape,
         })
      ),
      immunizations: array(
         pipe(
            strictObject({
               ...immunizationsEntryShape,
            }),
            forward(
               check(({ route, site }) => {
                  return route === 'intramuscular' || route === 'subcutaneous'
                     ? !!site
                     : !site;
               }, `Site selection is required for intramuscular or subcutaneous routes, and must be empty for other routes (valibot).`),
               ['site']
            ),
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
            ...surgicalHistoryEntryShape,
         })
      ),
      consents: array(
         pipe(
            strictObject({
               ...consentsEntryShape,
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
   } satisfies Record<keyof IPatientDocument['clinicalInfo'], GenericSchema>),
} satisfies Record<keyof IPatientDocument, GenericSchema>);

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
