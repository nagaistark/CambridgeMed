/* Default page size when the client sends no `limit`. */
export const paginationLimit = 10 as const;

/* Hard ceiling a client may request. Independent from the default on purpose. */
export const MAX_PAGE_SIZE = 50 as const;

/* Generous upper bound for opaque, base64url-encoded composite cursors. */
export const MAX_CURSOR_LENGTH = 512 as const;
