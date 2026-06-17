import mongoose from 'mongoose';

import {
   array,
   boolean,
   check,
   forward,
   InferOutput,
   intersect,
   object,
   optional,
   partialCheck,
   pick,
   pipe,
   regex,
   strictObject,
   transform,
} from 'valibot';
import {
   CursorPaginationSchema,
   baseString,
   stringDateInTheFutureOrOptionallyToday,
   stringDateInThePastOrOptionallyToday,
   dinRegex,
   idOrName,
   longString,
   nameString,
   objectIdStringCheck,
   phoneNANPRegex,
   positiveIntegerInputString,
   snomedRegex,
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
import { StrictSchemaDefinition_v4 } from '@utils/mongoose_types.ts';
import {
   shortDateRegex,
   postalCodeCanadaRegex,
} from '@utils/valibotSchemaReusables.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { AuditableResourceType } from '@ssot/audit_constants.ts';
import { LIST_PATIENT_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import { StrictIndexConfig } from '@utils/pathFinder.ts';

// ── Valibot subschemas ───────────────────────────────────────────────────────────
export const medicationVSchema = strictObject({
   id: baseString,
   name: baseString, // Brand or Generic name
   din: validateDIN, // Health Canada 8-digit Drug Identification Number
   snomedCode: optional(baseString), // Standard pan-Canadian electronic health record code
   form: makePicklist(medicationForms),
   route: makePicklist(medDeliveryRoutes),
   status: makePicklist(medicationStatuses),
   instructions: optional(longString),
   notes: optional(longString),
});

const allergyVSchema = strictObject({
   substance: baseString,
   reaction: longString,
   severity: makePicklist(medSeverityLevels),
   dateDiscovered: optional(stringDateInThePastOrOptionallyToday),
});

const immunizationVSchema = pipe(
   strictObject({
      name: baseString,
      din: validateDIN, // Health Canada Vaccine DIN
      form: makePicklist(vaccineForms),
      manufacturer: baseString,
      lotNumber: baseString,
      route: makePicklist(vaccineDeliveryRoutes),
      site: optional(makePicklist(vaccineDeliverySites)),
      dose: strictObject({
         value: positiveIntegerInputString,
         unit: makePicklist(vaccineDoseUnits),
      }),
      dateAdministered: stringDateInThePastOrOptionallyToday,
      refused: boolean(),
      refusedDate: optional(stringDateInThePastOrOptionallyToday),
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

const surgeryVSchema = strictObject({
   procedure: baseString,
   date: stringDateInThePastOrOptionallyToday,
   performedBy: idOrName,
   hospital: nameString,
   notes: optional(longString),
});

const consentVSchema = pipe(
   strictObject({
      type: baseString,
      granted: boolean(),
      date: optional(stringDateInThePastOrOptionallyToday),
      method: optional(makePicklist(consentCollectingMethods)),
      recordedBy: optional(objectIdStringCheck),
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

// ── Main Valibot registration schema ─────────────────────────────────────────────
export const patientVSchemaFull = strictObject({
   isActive: boolean(),
   primaryDoctorId: objectIdStringCheck,

   intakeInfo: strictObject({
      coreIdentifiers: pipe(
         strictObject({
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
            enrollmentDate: optional(stringDateInThePastOrOptionallyToday),
            enrollmentTerminationDate: optional(
               stringDateInTheFutureOrOptionallyToday
            ),
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
         expiryDate: validateExpiryDate,
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
            dateOfBirth: validateDOB,
            deceased: boolean(),
            dateOfDeath: optional(stringDateInThePastOrOptionallyToday),
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
               ageAtDiagnosed: optional(positiveIntegerInputString),
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
      activeMedications: array(medicationVSchema),
      allergies: array(allergyVSchema),
      immunizations: array(immunizationVSchema),
      surgicalHistory: array(surgeryVSchema),
      consents: array(consentVSchema),
   }),
});

export const patientVSchemaInitial = pick(patientVSchemaFull, [
   'isActive',
   'primaryDoctorId',
   'intakeInfo',
]);

export type IPatientDefinitionFull = InferOutput<typeof patientVSchemaFull>;
export type IPatientDefinitionInit = InferOutput<typeof patientVSchemaInitial>;

export type IPatientDocument = IPatientDefinitionFull & {
   _id: mongoose.Types.ObjectId;
   createdAt: Date;
   updatedAt: Date;
};

// ── HTTP response types ──────────────────────────────────────────────────────────
export type PatientCreateFullResponse = {
   success: true;
   message: string;
   patient: IPatientDocument; // Includes clinicalInfo
};

export type PatientCreateIntakeResponse = {
   success: true;
   message: string;
   patient: Omit<IPatientDocument, 'clinicalInfo'>;
};

// ── GET response types ───────────────────────────────────────────────────────────

type IntakeInfoKey = keyof Pick<IPatientDocument, 'intakeInfo'>;
type DemographicsKey = keyof Pick<
   IPatientDocument['intakeInfo'],
   'demographics'
>;
type CoreIdentifiersKey = keyof Pick<
   IPatientDocument['intakeInfo'],
   'coreIdentifiers'
>;

export type PatientSummary = Pick<
   IPatientDocument,
   '_id' | 'isActive' | 'primaryDoctorId' | 'createdAt' | 'updatedAt'
> & {
   [K in IntakeInfoKey]: {
      [D in DemographicsKey]: Pick<
         IPatientDocument['intakeInfo']['demographics'],
         'prefix' | 'firstName' | 'lastName' | 'dateOfBirth' | 'deceased'
      >;
   } & {
      [C in CoreIdentifiersKey]: Pick<
         IPatientDocument['intakeInfo']['coreIdentifiers'],
         'healthCardNumber' | 'chartNumber' | 'enrolledStatus'
      >;
   };
};

export type PatientGetFullResponse = {
   success: true;
   patient: IPatientDocument;
};

export type PatientGetIntakeResponse = {
   success: true;
   patient: Omit<IPatientDocument, 'clinicalInfo'>;
};

export type PatientCursorListResponse = {
   success: true;
   patients: PatientSummary[];
   pagination: {
      nextCursor: string | null;
      limit: number;
   };
};

// ── IntakeInfo types ─────────────────────────────────────────────────────────────
type IIntakeInfo = IPatientDefinitionFull['intakeInfo'];

type ICoreIdentifiers = IIntakeInfo['coreIdentifiers'];
type ISupplementalInsurance = IIntakeInfo['supplementalInsurance'];
type IPreferences = NonNullable<IIntakeInfo['preferences']>;
type IDemographics = IIntakeInfo['demographics'];
type ISocialHistory = IIntakeInfo['socialHistory'];
type IFamilyHistoryEntry = NonNullable<IIntakeInfo['familyHistory']>[number];
type IAccessibilityNeeds = NonNullable<IIntakeInfo['accessibilityNeeds']>;
type IAddressEntry = IIntakeInfo['contactInformation']['addresses'][number];
type IPhoneEntry = IIntakeInfo['contactInformation']['phones'][number];
type IContactInformation = IIntakeInfo['contactInformation'];
type IEmergencyContactsEntry = IIntakeInfo['emergencyContacts'][number];
type INextOfKin = NonNullable<IIntakeInfo['nextOfKin']>;

// ── IntakeInfo subschemas ────────────────────────────────────────────────────────
const CoreIdentifiersDefinition = {
   healthCardNumber: { type: String, required: true },
   healthCardVersion: { type: String, required: true },
   healthCardProvince: {
      type: String,
      enum: {
         values: provincesAndTerritories,
         message: `Must be one of the ${provincesAndTerritories.join(', ')}`,
      },
      required: true,
   },
   healthCardExpiryDate: {
      type: String,
      required: true,
      validate: {
         validator: function (dateStr: string) {
            return shortDateRegex.test(dateStr);
         },
         message: `Invalid Date Format (mongoose).`,
      },
   },
   chartNumber: { type: String, required: true },
   internalProviderId: { type: String, required: false },
   externalProviderId: { type: String, required: false },
   enrolledStatus: {
      type: String,
      enum: {
         values: enrollmentStatuses,
         message: `Must be one of the ${enrollmentStatuses.join(', ')}`,
      },
      required: false,
   },
   enrollmentDate: {
      type: Date,
      required: false,
   },
   enrollmentTerminationDate: {
      type: Date,
      required: false,
   },
   enrollmentTerminationReason: {
      type: String,
      required: false,
   },
} satisfies StrictSchemaDefinition_v4<ICoreIdentifiers>;

const CoreIdentifiersSchema = new mongoose.Schema<ICoreIdentifiers>(
   CoreIdentifiersDefinition,
   { _id: false }
);

const SupplementalInsuranceDefinition = {
   provider: {
      type: String,
      required: true,
   },
   policyNumber: {
      type: String,
      required: true,
   },
   groupNumber: {
      type: String,
   },
   expiryDate: {
      type: String,
      required: true,
      validate: {
         validator: function (dateStr: string) {
            return shortDateRegex.test(dateStr);
         },
         message: `Invalid Date Format (mongoose).`,
      },
   },
} satisfies StrictSchemaDefinition_v4<ISupplementalInsurance>;

const SupplementalInsuranceSchema = new mongoose.Schema<ISupplementalInsurance>(
   SupplementalInsuranceDefinition,
   { _id: false }
);

const PreferencesDefinition = {
   preferredLanguage: {
      type: String,
      enum: availableLanguages,
      required: true,
   },
   interpreterNeeded: {
      type: Boolean,
   },
} satisfies StrictSchemaDefinition_v4<IPreferences>;

const PreferencesSchema = new mongoose.Schema<IPreferences>(
   PreferencesDefinition,
   { _id: false }
);

const DemographicsDefinition = {
   prefix: {
      type: String,
      enum: prefixes,
   },
   firstName: {
      type: String,
      required: true,
   },
   lastName: {
      type: String,
      required: true,
   },
   suffix: {
      type: String,
      enum: suffixes,
   },
   dateOfBirth: {
      type: String,
      required: true,
      validate: {
         validator: function (dateStr: string) {
            return shortDateRegex.test(dateStr);
         },
         message: `Invalid Date Format (mongoose).`,
      },
   },
   deceased: {
      type: Boolean,
      required: true,
   },
   dateOfDeath: {
      type: Date,
      required: function (this: IDemographics): boolean {
         return this.deceased === true;
      },
      validate: {
         validator: function (
            this: IDemographics,
            dod: Date | null | undefined
         ): boolean {
            return this.deceased ? !!dod : !dod;
         },
         message: `Date of death is required if the patient is deceased, and must be empty otherwise (mongoose).`,
      },
   },
   sexAtBirth: {
      type: String,
      enum: sexes,
      required: true,
   },
   currentSex: {
      type: String,
      enum: sexes,
      required: true,
   },
} satisfies StrictSchemaDefinition_v4<IDemographics>;

const DemographicsSchema = new mongoose.Schema<IDemographics>(
   DemographicsDefinition,
   { _id: false }
);

const SocialHistoryDefinition = {
   occupation: { type: String, required: true },
   education: { type: String, enum: educationLevels, required: true },
   housingSituation: {
      type: String,
      enum: housingSituationVariants,
      required: true,
   },
   smokingStatus: { type: String, enum: smokingStatuses, required: true },
   alcoholUse: { type: String, enum: alcoholUseLevels, required: true },
   substanceUse: { type: String, enum: substanceUseLevels, required: true },
} satisfies StrictSchemaDefinition_v4<ISocialHistory>;

const SocialHistorySchema = new mongoose.Schema<ISocialHistory>(
   SocialHistoryDefinition,
   { _id: false }
);

const FamilyHistoryEntryDefinition = {
   relationship: { type: String, enum: familyRelationships, required: true },
   condition: { type: String, required: true },
   ageAtDiagnosed: { type: Number },
   deceased: { type: Boolean, required: true },
   notes: { type: String },
} satisfies StrictSchemaDefinition_v4<IFamilyHistoryEntry>;

const FamilyHistoryEntrySchema = new mongoose.Schema<IFamilyHistoryEntry>(
   FamilyHistoryEntryDefinition,
   { _id: false }
);

const AccessibilityNeedsDefinition = {
   mobilityAssistance: { type: Boolean },
   wheelchairAccess: { type: Boolean },
   hearingImpairment: { type: Boolean },
   visualImpairment: { type: Boolean },
   notes: { type: String },
} satisfies StrictSchemaDefinition_v4<IAccessibilityNeeds>;

const AccessibilityNeedsSchema = new mongoose.Schema<IAccessibilityNeeds>(
   AccessibilityNeedsDefinition,
   { _id: false }
);

const AddressEntryDefinition = {
   street: {
      type: String,
      required: true,
   },
   city: {
      type: String,
      required: true,
   },
   province: {
      type: String,
      enum: provincesAndTerritories,
      required: true,
   },
   postalCode: {
      type: String,
      required: true,
      validate: {
         validator: function (postalCodeStr: string) {
            return postalCodeCanadaRegex.test(postalCodeStr);
         },
         message: `Invalid Postal Code Format (mongoose).`,
      },
   },
   country: {
      type: String,
      enum: ['Canada', 'United States'],
      required: true,
      default: 'Canada',
   },
   isPrimary: {
      type: Boolean,
      required: true,
   },
} satisfies StrictSchemaDefinition_v4<IAddressEntry>;

const AddressEntrySchema = new mongoose.Schema<IAddressEntry>(
   AddressEntryDefinition,
   { _id: false }
);

const PhoneEntryDefinition = {
   type: {
      type: String,
      enum: typeOfPhones,
      required: true,
   },
   number: {
      type: String,
      required: true,
      validate: {
         validator: function (phoneNumber: string) {
            return phoneNANPRegex.test(phoneNumber);
         },
         message: `Invalid NANP phone format (mongoose).`,
      },
   },
   isPrimary: {
      type: Boolean,
      required: true,
   },
} satisfies StrictSchemaDefinition_v4<IPhoneEntry>;

const PhoneEntrySchema = new mongoose.Schema<IPhoneEntry>(
   PhoneEntryDefinition,
   { _id: false }
);

const ContactInformationDefinition = {
   addresses: [AddressEntrySchema],
   phones: [PhoneEntrySchema],
} satisfies StrictSchemaDefinition_v4<IContactInformation>;

const ContactInformationSchema = new mongoose.Schema<IContactInformation>(
   ContactInformationDefinition,
   { _id: false }
);

const EmergencyContactsEntryDefinition = {
   name: {
      type: String,
      required: true,
   },
   relationship: {
      type: String,
      enum: familyRelationships,
      required: true,
   },
   phone: {
      type: String,
      required: true,
      validate: {
         validator: function (phoneNumber: string) {
            return phoneNANPRegex.test(phoneNumber);
         },
         message: `Invalid NANP phone format (mongoose).`,
      },
   },
} satisfies StrictSchemaDefinition_v4<IEmergencyContactsEntry>;

const EmergencyContactsEntrySchema =
   new mongoose.Schema<IEmergencyContactsEntry>(
      EmergencyContactsEntryDefinition,
      { _id: false }
   );

const NextOfKinDefinition = {
   name: {
      type: String,
      required: true,
   },
   relationship: {
      type: String,
      enum: familyRelationships,
      required: true,
   },
   phone: {
      type: String,
      required: true,
      validate: {
         validator: function (phoneNumber: string) {
            return phoneNANPRegex.test(phoneNumber);
         },
         message: `Invalid NANP phone format (mongoose).`,
      },
   },
} satisfies StrictSchemaDefinition_v4<INextOfKin>;

const NextOfKinSchema = new mongoose.Schema<INextOfKin>(NextOfKinDefinition, {
   _id: false,
});

const IntakeInfoDefinition = {
   coreIdentifiers: CoreIdentifiersSchema,
   supplementalInsurance: SupplementalInsuranceSchema,
   preferences: {
      type: PreferencesSchema,
      required: false,
      default: undefined,
   },
   demographics: DemographicsSchema,
   socialHistory: SocialHistorySchema,
   familyHistory: [FamilyHistoryEntrySchema],
   accessibilityNeeds: {
      type: AccessibilityNeedsSchema,
      required: false,
      default: undefined,
   },
   contactInformation: ContactInformationSchema,
   emergencyContacts: [EmergencyContactsEntrySchema],
   nextOfKin: {
      type: NextOfKinSchema,
      required: false,
      default: undefined,
   },
} satisfies StrictSchemaDefinition_v4<IIntakeInfo>;

const IntakeInfoSchema = new mongoose.Schema<IIntakeInfo>(
   IntakeInfoDefinition,
   { _id: false }
);

// ── ClinicalInfo types ───────────────────────────────────────────────────────────

type IActiveMedicationsEntry =
   IPatientDefinitionFull['clinicalInfo']['activeMedications'][number];
type IAllergiesEntry =
   IPatientDefinitionFull['clinicalInfo']['allergies'][number];
type IImmunizationDose =
   IPatientDefinitionFull['clinicalInfo']['immunizations'][number]['dose'];
type IImmunizationsEntry =
   IPatientDefinitionFull['clinicalInfo']['immunizations'][number];
type ISurgicalHistoryEntry =
   IPatientDefinitionFull['clinicalInfo']['surgicalHistory'][number];
type IConsentsEntry =
   IPatientDefinitionFull['clinicalInfo']['consents'][number];
type IClinicalInfo = IPatientDefinitionFull['clinicalInfo'];

// ── ClinicalInfo subschemas ──────────────────────────────────────────────────────
const ActiveMedicationsEntryDefinition = {
   id: { type: String, required: true },
   name: { type: String, required: true },
   din: {
      type: String,
      required: true,
      validate: {
         validator: function (dinStr: string) {
            return dinRegex.test(dinStr);
         },
         message: `Invalid DIN number (mongoose).`,
      },
   },
   snomedCode: {
      type: String,
      validate: {
         validator: function (snomedStr: string) {
            return snomedRegex.test(snomedStr);
         },
         message: `Invalid SNOMED code (mongoose).`,
      },
   },
   form: {
      type: String,
      enum: medicationForms,
      required: true,
   },
   route: {
      type: String,
      enum: medDeliveryRoutes,
      required: true,
   },
   status: {
      type: String,
      enum: medicationStatuses,
      required: true,
   },
   instructions: {
      type: String,
   },
   notes: {
      type: String,
   },
} satisfies StrictSchemaDefinition_v4<IActiveMedicationsEntry>;

const ActiveMedicationsEntrySchema =
   new mongoose.Schema<IActiveMedicationsEntry>(
      ActiveMedicationsEntryDefinition,
      { _id: false }
   );

const AllergesEntryDefinition = {
   substance: { type: String, required: true },
   reaction: { type: String, required: true },
   severity: { type: String, enum: medSeverityLevels, required: true },
   dateDiscovered: { type: Date },
} satisfies StrictSchemaDefinition_v4<IAllergiesEntry>;

const AllergesEntrySchema = new mongoose.Schema<IAllergiesEntry>(
   AllergesEntryDefinition,
   { _id: false }
);

const ImmunizationDoseDefinition = {
   value: { type: Number, required: true },
   unit: { type: String, enum: vaccineDoseUnits, required: true },
} satisfies StrictSchemaDefinition_v4<IImmunizationDose>;

const ImmunizationDoseSchema = new mongoose.Schema<IImmunizationDose>(
   ImmunizationDoseDefinition,
   { _id: false }
);

const ImmunizationsEntryDefinition = {
   name: { type: String, required: true },
   din: {
      type: String,
      required: true,
      validate: {
         validator: function (dinStr: string) {
            return dinRegex.test(dinStr);
         },
         message: `Invalid DIN number (mongoose).`,
      },
   },
   form: { type: String, enum: vaccineForms, required: true },
   manufacturer: { type: String, required: true },
   lotNumber: { type: String, required: true },
   route: { type: String, enum: vaccineDeliveryRoutes, required: true },
   site: {
      type: String,
      enum: vaccineDeliverySites,
      validate: {
         validator: function (this: IImmunizationsEntry, siteStr: string) {
            return this.route === 'intramuscular' ||
               this.route === 'subcutaneous'
               ? !!siteStr
               : !siteStr;
         },
         message: `Site selection is required for intramuscular or subcutaneous routes, and must be empty for other routes (mongoose).`,
      },
   },
   dose: ImmunizationDoseSchema,
   dateAdministered: { type: Date, required: true },
   refused: { type: Boolean, required: true },
   refusedDate: {
      type: Date,
      required: function (this: IImmunizationsEntry): boolean {
         return this.refused === true;
      },
      validate: {
         validator: function (
            this: IImmunizationsEntry,
            refDate: Date | null | undefined
         ): boolean {
            return this.refused ? !!refDate : !refDate;
         },
         message: `Refused date must be provided if and only if the vaccine was refused (mongoose).`,
      },
   },
   notes: { type: String },
} satisfies StrictSchemaDefinition_v4<IImmunizationsEntry>;

const ImmunizationsEntrySchema = new mongoose.Schema<IImmunizationsEntry>(
   ImmunizationsEntryDefinition,
   { _id: false }
);

const SurgicalHistoryEntryDefinition = {
   procedure: { type: String, required: true },
   date: { type: Date, required: true },
   performedBy: { type: String, required: true },
   hospital: { type: String, required: true },
   notes: { type: String },
} satisfies StrictSchemaDefinition_v4<ISurgicalHistoryEntry>;

const SurgicalHistoryEntrySchema = new mongoose.Schema<ISurgicalHistoryEntry>(
   SurgicalHistoryEntryDefinition,
   { _id: false }
);

const ConsentsEntryDefinition = {
   type: { type: String, required: true },
   granted: { type: Boolean, required: true },
   date: {
      type: Date,
      required: function (this: IConsentsEntry): boolean {
         return this.granted === true;
      },
      validate: {
         validator: function (this: IConsentsEntry, dateCon: string): boolean {
            return this.granted ? !!dateCon : !dateCon;
         },
         message: `When consent is granted, the date is required (mongoose).`,
      },
   },
   method: {
      type: String,
      enum: consentCollectingMethods,
      required: function (this: IConsentsEntry): boolean {
         return this.granted;
      },
      validate: {
         validator: function (
            this: IConsentsEntry,
            m: (typeof consentCollectingMethods)[number]
         ): boolean {
            return this.granted ? !!m : !m;
         },
         message: `When consent is granted, the method is required (mongoose).`,
      },
   },
   recordedBy: {
      type: String,
      required: function (this: IConsentsEntry): boolean {
         return this.granted === true;
      },
      validate: {
         validator: function (this: IConsentsEntry, rec: string): boolean {
            return this.granted ? !!rec : !rec;
         },
         message: `When consent is granted, you need to specify who it's recorded by (mongoose).`,
      },
   },
} satisfies StrictSchemaDefinition_v4<IConsentsEntry>;

const ConsentsEntrySchema = new mongoose.Schema<IConsentsEntry>(
   ConsentsEntryDefinition,
   { _id: false }
);

const ClinicalInfoDefinition = {
   bloodType: {
      type: String,
      enum: bloodTypes,
      required: true,
      default: 'unknown',
   },
   activeMedications: [ActiveMedicationsEntrySchema],
   allergies: [AllergesEntrySchema],
   immunizations: [ImmunizationsEntrySchema],
   surgicalHistory: [SurgicalHistoryEntrySchema],
   consents: [ConsentsEntrySchema],
} satisfies StrictSchemaDefinition_v4<IClinicalInfo>;

const ClinicalInfoSchema = new mongoose.Schema<IClinicalInfo>(
   ClinicalInfoDefinition,
   { _id: false }
);

// ── Main Mongoose schema definition ──────────────────────────────────────────────
const PatientDefinition = {
   isActive: {
      type: Boolean,
      required: true,
      default: true,
   },
   primaryDoctorId: {
      type: String,
      required: true,
   },
   intakeInfo: IntakeInfoSchema,
   clinicalInfo: ClinicalInfoSchema,
} satisfies StrictSchemaDefinition_v4<IPatientDefinitionFull>;

export const PatientSchema = new mongoose.Schema<IPatientDocument>(
   PatientDefinition,
   {
      timestamps: true,
      strict: 'throw',
   }
);

// ── Indexes ──────────────────────────────────────────────────────────────────────

PatientSchema.index({
   'intakeInfo.demographics.lastName': 1,
   'intakeInfo.demographics.firstName': 1,
} satisfies StrictIndexConfig<IPatientDefinitionInit>);

PatientSchema.index(
   {
      'intakeInfo.contactInformation.phones.number': 1,
      'intakeInfo.coreIdentifiers.healthCardNumber': 1,
   } satisfies StrictIndexConfig<IPatientDefinitionInit>,
   { unique: true }
);

PatientSchema.index(
   {
      'intakeInfo.demographics.lastName': 'text',
      'intakeInfo.demographics.firstName': 'text',
      'intakeInfo.coreIdentifiers.healthCardNumber': 'text',
      'intakeInfo.coreIdentifiers.chartNumber': 'text',
   } satisfies StrictIndexConfig<IPatientDefinitionInit>,
   {
      name: 'PatientSearchIndex',
   }
);

const modelName: Extract<AuditableResourceType, 'Patient'> = 'Patient';

export const getPatientModel = createModelGetter<IPatientDocument>(
   () => DatabaseManager.getInstance().clinic.connection,
   modelName,
   PatientSchema
);

// ── GET /api/patients ────────────────────────────────────────────────────────────
const ListPatientFilterSchema = object({
   search: optional(baseString),
   includeArchived: optional(
      pipe(
         baseString,
         transform((val: string): boolean => {
            return val.toLowerCase() === 'true';
         })
      )
   ),
});

export const PatientQuerySchema = intersect([
   CursorPaginationSchema,
   ListPatientFilterSchema,
]);

export type ListPatientsQuery = InferOutput<typeof PatientQuerySchema>;

export const PATIENT_LIST_SEARCH_FIELDS = [
   'intakeInfo.demographics.lastName',
   'intakeInfo.demographics.firstName',
   'intakeInfo.coreIdentifiers.healthCardNumber',
   'intakeInfo.coreIdentifiers.chartNumber',
] as const satisfies ReadonlyArray<keyof typeof LIST_PATIENT_PROJECTION>;
