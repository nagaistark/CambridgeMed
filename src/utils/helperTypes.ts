export type ExtractKeysMatching<T, Pattern extends string> = {
   [K in keyof T]-?: K extends Pattern ? K : never;
}[keyof T];
