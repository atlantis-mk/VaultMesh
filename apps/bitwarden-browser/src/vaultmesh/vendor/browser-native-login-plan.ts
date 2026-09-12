import { z } from 'zod';

/** Optional browser.autofill.execute input; never a decrypted CipherView. */
export const NativeLoginPlanSchema = z.array(z.object({
  handle: z.string().uuid(),
  source: z.enum(['username', 'password', 'totpCode', 'custom']),
  index: z.number().int().min(0).max(299).optional(),
  name: z.string().min(1).max(1024).optional(),
}).strict().refine((entry) => entry.source === 'custom'
  ? entry.index !== undefined && entry.name !== undefined
  : entry.source === 'totpCode'
    ? entry.name === undefined && (entry.index === undefined || entry.index < 6)
    : entry.index === undefined && entry.name === undefined
)).min(1).max(300).refine((entries) => new Set(entries.map((entry) => entry.handle)).size === entries.length);
export type NativeLoginPlan = z.infer<typeof NativeLoginPlanSchema>;
