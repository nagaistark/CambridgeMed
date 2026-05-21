export const MIN_LEGAL_AGE = 18 as const;
export const MAX_LEGAL_AGE = 130 as const;

export const months = [
   'JAN',
   'FEB',
   'MAR',
   'APR',
   'MAY',
   'JUN',
   'JUL',
   'AUG',
   'SEP',
   'OCT',
   'NOV',
   'DEC',
] as const;
export const provincesAndTerritories = [
   'ON',
   'QC',
   'NS',
   'NB',
   'MB',
   'BC',
   'PE',
   'SK',
   'AB',
   'NL',
   'NT',
   'YT',
   'NU',
] as const;
export const typeOfPhones = ['home', 'mobile', 'work', 'other'] as const;
export const prefixes = [
   'Mr.',
   'Mrs.',
   'Ms.',
   'Miss',
   'Dr.',
   'Prof.',
   'Rev.',
   'Hon.',
] as const;
export const suffixes = [
   'Jr.',
   'Sr.',
   'II',
   'III',
   'IV',
   'MD',
   'PhD',
   'QC',
   'Esq.',
   'CPA',
   'MBA',
] as const;
export const availableLanguages = ['English', 'Français'] as const;
