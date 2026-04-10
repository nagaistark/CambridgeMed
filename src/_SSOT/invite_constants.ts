// Raw invite tokens are 48 random bytes encoded as hex → 96 characters. Shared between `previewInviteController` and `acceptInviteController`. If the token generation strategy ever changes, this is the one place to update.
export const INVITE_TOKEN_REGEX = /^[a-f0-9]{96}$/i;
