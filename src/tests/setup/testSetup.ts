import { beforeAll, afterAll } from 'vitest';
import { DatabaseManager } from 'dbConnect.ts';

beforeAll(async () => {
   await DatabaseManager.getInstance().initialize();
});

afterAll(async () => {
   await DatabaseManager.getInstance().cleanup();
});
