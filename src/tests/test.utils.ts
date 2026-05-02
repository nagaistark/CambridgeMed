import { DatabaseManager } from 'dbConnect.ts';

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

export const testUsername = 'jascha.stark' as const;
export const testDomain = 'gmail.com' as const;

export async function wipeCollections(): Promise<void> {
   const manager = DatabaseManager.getInstance();

   const authConn = manager.auth.connection;
   const clinicConn = manager.clinic.connection;

   await Promise.all([
      ...Object.values(authConn?.collections ?? {}).map(c => c.deleteMany({})),
      ...Object.values(clinicConn?.collections ?? {}).map(c =>
         c.deleteMany({})
      ),
   ]);
}
