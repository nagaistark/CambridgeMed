import { Settings } from 'luxon';

/* The clinic's operating timezone and locale. These are the single source of truth for all date/time operations across the application. Import this module as a SIDE EFFECT (import '@ssot/date_time_constants.ts') in the entry point (currently, `server.ts`) to configure Luxon globally before any other code runs. */
export const TIME_ZONE = 'America/Toronto' as const;
export const LOCALE = 'en-CA' as const;
export const RESET_WEEKDAY = 1; //  // Luxon-based weekdays: 1 — Monday, 7 — Sunday;

Settings.defaultZone = TIME_ZONE;
Settings.defaultLocale = LOCALE;
