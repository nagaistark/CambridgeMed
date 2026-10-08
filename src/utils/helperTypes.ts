export type ExtractKeysMatching<T, Pattern extends string> = {
   [K in keyof T]-?: K extends Pattern ? K : never;
}[keyof T];

export type NonNullableProps<T> = {
   [K in keyof T]: NonNullable<T[K]>;
};

/* A fragment is either "no constraint" or exactly the shape T. The `Record<string, never>` arm rejects any key written into the empty branch, so a typo like `{ nonExistingField: true }` becomes a compile error. */
export type EmptyOr<T> = Record<string, never> | T;
