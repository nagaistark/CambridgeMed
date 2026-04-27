import { beforeAll, afterAll, afterEach } from 'vitest';
import { DatabaseManager } from 'dbConnect.ts';

// Runs once before all tests in this worker's current file.
beforeAll(async () => {
   await DatabaseManager.getInstance().initialize();
});

// Runs once after all tests in this worker's current file.
afterAll(async () => {
   await DatabaseManager.getInstance().cleanup();
});

// Runs after EVERY individual test — the "clean counter between dishes" step. We wipe both connections' collections so no test leaves state behind.
afterEach(async () => {
   const manager = DatabaseManager.getInstance();

   const authConn = manager.auth.connection;
   const clinicConn = manager.clinic.connection;

   // Wipe every collection on both connections in parallel.
   await Promise.all([
      ...Object.values(authConn?.collections ?? {}).map(c => c.deleteMany({})),
      ...Object.values(clinicConn?.collections ?? {}).map(c =>
         c.deleteMany({})
      ),
   ]);
});
