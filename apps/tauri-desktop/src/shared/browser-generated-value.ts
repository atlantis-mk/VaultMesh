import { z } from 'zod';
export const GeneratedValueSchema = z.object({
  mode: z.enum(['password', 'passphrase', 'username', 'uuid']),
  value: z.string().min(1).max(1024).refine((value) => !/[\u0000-\u001f\u007f]/.test(value)),
}).strict();
