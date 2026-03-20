// Is going to be used in case of a User changing the email.

// In the jose library, the setExpirationTime() method accepts a human-readable time span (e.g., '2h', '7d', '15m'). The library resolves this into a duration added to the current Unix timestamp.

const timeUnits = {
   s: 'second',
   m: 'minute',
   h: 'hour',
   d: 'day',
   w: 'week',
   y: 'year',
} as const;

type TimeUnit = keyof typeof timeUnits;
type VerificationTokenExpiry = `${number}${TimeUnit}`;
export const VERIFICATION_TOKEN_EXPIRY: VerificationTokenExpiry = '15m';
export const HUMANIZED_EXPIRY = formatDuration(VERIFICATION_TOKEN_EXPIRY);

function formatDuration(str: VerificationTokenExpiry) {
   const duration: string = str.slice(0, -1);
   const unit = str.slice(-1) as TimeUnit;
   const result = timeUnits[unit];
   return `${duration} ${duration === '1' ? result : `${result}s`}`;
}

export const EMAIL_VERIFICATION_AUDIENCE = 'email-verification' as const;
