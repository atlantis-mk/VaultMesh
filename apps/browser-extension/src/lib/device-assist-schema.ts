import { z } from 'zod';
export const DeviceAssistCandidateSchema = z.object({
  id: z.string().max(128), peer: z.string().max(128), device: z.string().max(256),
  kind: z.enum(['phone','sms']), source: z.string().max(128), receivedAt: z.number().int().nonnegative().optional(), remainingMs: z.number().int().min(0).max(120_000),
}).strict();
export const DeviceAssistStateSchema = z.object({
  busy: z.boolean(), failed: z.boolean(), ready: z.boolean(), candidates: z.array(DeviceAssistCandidateSchema).max(20),
}).strict();
export type DeviceAssistCandidate = z.infer<typeof DeviceAssistCandidateSchema>;
