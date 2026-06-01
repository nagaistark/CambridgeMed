/* Escapes all regex metacharacters in a string so it can be safely interpolated into a RegExp constructor without altering its literal meaning. Without this, user-supplied input like "(.*)" would be interpreted as a wildcard pattern rather than the literal characters "(.*)", which could match unintended documents or trigger catastrophic backtracking on certain regex engines. */
export function escapeRegex(str: string): string {
   return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
