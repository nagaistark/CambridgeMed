// All the deterministic hashes across the projects are 32 bytes from crypto.randomBytes (that produce 64 character long string)
export const HEX64_REGEX = /^[a-f0-9]{64}$/i;

export const hexHashValidator = {
   validator: (str: string) => HEX64_REGEX.test(str),
   message: `Must be a 64-character hex string (SHA-256 digest).`,
};
