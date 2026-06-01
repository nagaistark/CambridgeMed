export const enrollmentStatuses = [
   'enrolled',
   'pending',
   'inactive',
   'declined',
   'unspecified',
] as const;
export const sexes = ['male', 'female', 'intersex'] as const;
export const smokingStatuses = ['never', 'former', 'current'] as const;
export const educationLevels = [
   'none',
   'primary',
   'secondary',
   'college',
   'university',
   'postgraduate',
] as const;
export const housingSituationVariants = [
   'stable',
   'temporary',
   'homeless',
   'supported',
   'unknown',
] as const;
export const alcoholUseLevels = [
   'none',
   'occasional',
   'regular',
   'heavy',
] as const;
export const substanceUseLevels = [
   'none',
   'occasional',
   'regular',
   'dependence',
   'unknown',
] as const;
export const familyRelationships = [
   'mother',
   'father',
   'brother',
   'sister',
   'daughter',
   'son',
   'maternal grandmother',
   'paternal grandmother',
   'maternal grandfather',
   'paternal grandfather',
   'maternal aunt',
   'paternal aunt',
   'maternal uncle',
   'paternal uncle',
   'maternal niece',
   'paternal niece',
   'maternal nephew',
   'paternal nephew',
   'other',
] as const;
export const bloodTypes = [
   'unknown',
   'O+',
   'O-',
   'A+',
   'A-',
   'B+',
   'B-',
   'AB+',
   'AB-',
] as const;
export const medicationSources = [
   'clinic',
   'patientReported',
   'external',
] as const;
export const medicationStatuses = [
   'active',
   'completed',
   'discontinued',
] as const;
export const prescriptionStatuses = [
   'draft',
   'signed',
   'dispensed',
   'cancelled',
   'expired',
] as const;
export const medSeverityLevels = ['low', 'moderate', 'high'] as const;
export const encounterTypes = ['office', 'phone', 'telemedecine'] as const;
export const encounterStatuses = [
   'in-progress',
   'completed',
   'cancelled',
] as const;
export const encounterVisitOptions = [
   'initial',
   'follow-up',
   'consult',
   'annual',
   'urgent',
] as const;
export const medicationForms = [
   'tablet',
   'capsule',
   'oral solution',
   'oral suspension',
   'topical cream',
   'topical ointment',
   'inhaler',
   'injection',
   'eye drops',
   'ear drops',
   'nasal spray',
] as const;
export const medDoseUnits = [
   'mg',
   'g',
   'mcg',
   'ml',
   'tsp',
   'tbsp',
   'puff',
   'tablet(s)',
   'capsule(s)',
   'units',
] as const;
export const medDeliveryRoutes = [
   'oral',
   'sublingual',
   'buccal',
   'topical',
   'transdermal',
   'ophthalmic',
   'otic',
   'nasal',
   'inhalation',
   'intravenous',
   'intramuscular',
   'subcutaneous',
   'intradermal',
   'rectal',
   'vaginal',
   'urethral',
   'intraarticular',
   'intrathecal',
   'epidural',
   'intranasal',
   'intraocular',
   'inhaled (oral)',
   'oral rinse',
   'mouth/throat',
   'other',
] as const;
export const medFrequencies = [
   'QD', // Every day
   'BID', // Twice a day
   'TID', // Three times a day
   'QID', // Four times a day
   'QHS', // Every night at bedtime
   'Q4H', // Every 4 hours
   'Q6H', // Every 6 hours
   'PRN', // As needed
   'STAT', // Immediately
   'weekly', // Once a week
   'biweekly', // Twice a week
   'monthly', // One a month
] as const;
export const vaccineForms = [
   'vial',
   'pre-filled syringe',
   'nasal spray',
   'oral suspension',
] as const;
export const vaccineDoseUnits = ['mL', 'units'] as const;
export const vaccineDeliveryRoutes = [
   'intramuscular',
   'subcutaneous',
   'intranasal',
   'oral',
] as const;
export const vaccineDeliverySites = [
   'left deltoid',
   'right deltoid',
   'left vastus lateralis',
   'right vastus lateralis',
   'alternate site',
] as const;
export const appointmentStatuses = [
   'booked',
   'cancelled',
   'no-show',
   'completed',
] as const;
export const consentCollectingMethods = ['verbal', 'paper'] as const;
