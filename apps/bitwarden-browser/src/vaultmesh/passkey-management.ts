import { z } from "zod";
import { SecretItemSummarySchema } from "./vendor/model-contracts";
export const PasskeyManagementSchema = z.discriminatedUnion("verb", [
  z.object({ verb: z.literal("list"), loginId: z.uuid() }).strict(),
  z.object({ verb: z.literal("delete"), loginId: z.uuid(), id: z.uuid(), confirmed: z.literal(true) }).strict(),
]);
export type PasskeyManagement = z.infer<typeof PasskeyManagementSchema>;
export const PasskeyRowsSchema = z.array(SecretItemSummarySchema).max(10000);
export type PasskeyRows = z.infer<typeof PasskeyRowsSchema>;
export function passkeysForLogin(value: unknown, loginId: string): PasskeyRows {
  return PasskeyRowsSchema.parse(value).filter((row) => row.isPasskey && row.loginId === loginId);
}
