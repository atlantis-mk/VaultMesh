import { z } from 'zod';

// Closed sources only; values are resolved by the desktop for one approved handle.
export const NativeItemSourceSchema = z.enum([
  'card:cardholderName', 'card:number', 'card:code', 'card:brand',
  'card:expMonth', 'card:expYear', 'card:exp',
  'identity:fullName', 'identity:firstName', 'identity:middleName', 'identity:lastName',
  'identity:email', 'identity:address1', 'identity:address2', 'identity:fullAddress',
  'identity:postalCode', 'identity:city', 'identity:state', 'identity:country',
  'identity:phone', 'identity:company',
]);
export const NativeItemPlanSchema = z.array(z.object({
  handle: z.string().uuid(), source: NativeItemSourceSchema,
}).strict()).min(1).max(300).refine((entries) => new Set(entries.map((entry) => entry.handle)).size === entries.length);
export type NativeItemSource = z.infer<typeof NativeItemSourceSchema>;

