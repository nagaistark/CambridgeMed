/* Single source of truth for which route params are secrets and must never reach the logs unredacted. Add a name here, not a shape to a regex. */
export const SENSITIVE_URL_PARAM_NAMES = ['token'] as const;

/* Defense-in-depth only: catches token-shaped strings that slip past the params-based redaction above (e.g. a request that never matched a route, so req.params is empty). Lower bound of 32 keeps 24-char ObjectIds (harmless, useful in logs) from being swept up too. */
export const FALLBACK_HEX_SECRET_PATTERN = /[a-f0-9]{32,}/gi;
