import { z } from "zod";
import { clearManagedSecrets } from "./managed-items";
import { clearEmail } from "./email-otp";

// Projections of the existing LoginItemDetail / LoginItemUpdate RPC contracts.
// In particular, detail is a privileged edit read because custom fields contain values.
const text = (max: number, min = 0) => z.string().min(min).max(max)
  .refine((value) => new TextEncoder().encode(value).length <= max);
const customField = z.object({ label: text(256, 1), value: text(10_000) });
const metadata = {
  title: text(256, 1).refine((value) => value.trim().length > 0),
  username: text(2_048),
  url: text(10_000).nullable(),
  notes: text(10_000).nullable(),
  folder: text(256).nullable(),
  favorite: z.boolean(),
  additionalUrls: z.array(text(10_000, 1)).max(20),
  autofillOnPageLoad: z.boolean(),
  masterPasswordReprompt: z.boolean(),
  customFields: z.array(customField).max(50),
};

export const LoginDetailSchema = z.object({
  ...metadata,
  id: z.string().uuid(),
  hasTotpSecret: z.boolean(),
  hasRecoveryCodes: z.boolean(),
});
export type LoginDetail = z.infer<typeof LoginDetailSchema>;

export const LoginSaveSchema = z.object({
  ...metadata,
  id: z.string().uuid().optional(),
  password: text(10_000, 1).nullable(),
  totpSecret: text(10_000, 1).nullable(),
  // Core and file parser bound recovery codes by UTF-16 units, not UTF-8 bytes.
  recoveryCodes: z.array(z.string().min(1).max(256).refine((code) => code.trim().length > 0)).max(100).nullable(),
  clearTotpSecret: z.boolean(),
  clearRecoveryCodes: z.boolean(),
}).strict().superRefine((value, context) => {
  if ((!value.id && (!value.password || value.recoveryCodes === null || value.clearTotpSecret || value.clearRecoveryCodes)) ||
      (value.clearTotpSecret && value.totpSecret !== null) ||
      (value.clearRecoveryCodes && value.recoveryCodes !== null) ||
      (value.id && value.recoveryCodes?.length === 0)) {
    context.addIssue({ code: "custom", message: "Invalid login edit" });
  }
});
export type LoginSave = z.infer<typeof LoginSaveSchema>;

/** Drop our references, including nested values; JavaScript cannot promise memory zeroization. */
export function clearLoginSecrets(value: unknown): void {
  clearManagedSecrets(value);
  clearEmail(value);
  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  for (const key of ["masterPassword", "password", "totpSecret"]) {
    if (typeof record[key] === "string") record[key] = "";
  }
  for (const key of ["recoveryCodes", "codes"]) {
    if (Array.isArray(record[key])) {
      record[key].fill("");
      record[key].length = 0;
    }
  }
  if (Array.isArray(record.customFields)) {
    for (const field of record.customFields) {
      if (field && typeof field === "object" && "value" in field) field.value = "";
    }
  }
}
