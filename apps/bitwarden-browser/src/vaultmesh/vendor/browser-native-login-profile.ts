import { z } from 'zod';

/** Safe planning metadata. Custom values and TOTP seeds never cross this boundary. */
export const NativeLoginProfileSchema = z.object({
  id: z.string().uuid(),
  customFields: z.array(z.object({
    index: z.number().int().min(0).max(299),
    name: z.string().min(1).max(1024),
  }).strict()).max(300),
}).strict();
