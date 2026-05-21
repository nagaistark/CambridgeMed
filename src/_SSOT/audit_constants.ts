export const auditableResourceTypes = [
   'Patient',
   'Prescription',
   'Appointment',
   'LabResult',
   'Referral',
] as const;

export type AuditableResourceType = (typeof auditableResourceTypes)[number];

export const auditActions = ['CREATE', 'READ', 'UPDATE', 'DELETE'] as const;
export type AuditAction = (typeof auditActions)[number];
