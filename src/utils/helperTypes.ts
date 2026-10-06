export type ExtractKeysMatching<T, Pattern extends string> = {
   [K in keyof T]-?: K extends Pattern ? K : never;
}[keyof T];

export type NonNullableProps<T> = {
   [K in keyof T]: NonNullable<T[K]>;
};
