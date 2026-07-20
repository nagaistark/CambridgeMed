import { PatientSummary } from '@models/Patient_v3.model.ts';
import { ObjectId } from 'mongodb';

type PatientCursorData = [lastName: string, firstName: string, id: ObjectId];

export function encodeCursor(patient: PatientSummary): string {
   const cursorData: PatientCursorData = [
      patient.intakeInfo.demographics.lastName,
      patient.intakeInfo.demographics.firstName,
      patient._id,
   ];
   // Convert the array to a JSON string, then encode it as Base64 so the frontend just sees a random string
   return Buffer.from(JSON.stringify(cursorData)).toString('base64url');
}

export function decodeCursor(cursorString: string): PatientCursorData | null {
   try {
      const decoded = Buffer.from(cursorString, 'base64url').toString('utf-8');
      const parsed = JSON.parse(decoded);

      // Basic runtime validation to fail-fast if a user tampers with the cursor
      if (Array.isArray(parsed) && parsed.length === 3) {
         return parsed as PatientCursorData;
      }
      return null;
   } catch {
      return null; // If decoding fails, treat it as a bad request or start from the beginning
   }
}
