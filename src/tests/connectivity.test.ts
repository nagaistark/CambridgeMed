import { describe, it, expect } from 'vitest';
import { DatabaseManager } from 'dbConnect.ts';

describe('Database connectivity', () => {
   it('should have both connections in ready state', () => {
      const manager = DatabaseManager.getInstance();

      // readyState 1 means "connected" in Mongoose
      expect(manager.auth.connection?.readyState).toBe(1);
      expect(manager.clinic.connection?.readyState).toBe(1);
   });
});
