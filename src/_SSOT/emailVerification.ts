// In the jose library, the setExpirationTime() method accepts a human-readable time span (e.g., '2h', '7d', '15m'). The library resolves this into a duration added to the current Unix timestamp.
type VerificationTokenExpiry = `${number}${'s' | 'm' | 'h' | 'd' | 'w' | 'y'}`;
export const VERIFICATION_TOKEN_EXPIRY_MIN: VerificationTokenExpiry = '15m';

export const EMAIL_VERIFICATION_AUDIENCE: string = 'email-verification';
