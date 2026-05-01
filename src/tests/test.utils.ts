export type Optionalize<T> = {
   [K in keyof T]?: T[K];
};

export type OptionalizeExcept<T, X extends keyof T> = {
   [K in Exclude<keyof T, X>]?: T[K];
} & {
   [K in X]-?: T[K];
};

export const testToken =
   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as const;

export const testPassword = 'testPassword' as const;

export const testUsername = 'invited' as const;
export const testDomain = 'example.com' as const;
