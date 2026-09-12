import { z } from 'zod';

// Closed sources only; values are resolved by the desktop for one approved handle.
export const NativeItemSourceSchema = z.enum([
  'card:cardholderName', 'card:number', 'card:code', 'card:brand',
  'card:expMonth', 'card:expYear', 'card:exp',
  'identity:fullName', 'identity:firstName', 'identity:middleName', 'identity:lastName',
  'identity:email', 'identity:address1', 'identity:address2', 'identity:fullAddress',
  'identity:postalCode', 'identity:city', 'identity:state', 'identity:country',
  'identity:phone', 'identity:company',
  'ssh:title', 'ssh:publicKey', 'ssh:privateKey', 'ssh:keyPassphrase',
  'ssh:host', 'ssh:port', 'ssh:username', 'ssh:password',
  'secret:api-key', 'secret:access-token', 'secret:authenticator-key',
  'secret:client-secret', 'secret:webhook-secret', 'secret:database-credential',
  'secret:recovery-codes', 'secret:certificate', 'secret:software-license',
  'secret:identity-document', 'secret:secure-note', 'secret:crypto-wallet', 'secret:other',
  'secret:account', 'secret:provider',
]);
export const NativeItemPlanSchema = z.array(z.object({
  handle: z.string().uuid(), source: NativeItemSourceSchema,
}).strict()).min(1).max(300).refine((entries) => new Set(entries.map((entry) => entry.handle)).size === entries.length);
export type NativeItemSource = z.infer<typeof NativeItemSourceSchema>;
