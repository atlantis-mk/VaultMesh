import { z } from "zod";
export const EMAIL_SELECT = "vaultmesh.native-email.select";
export const EMAIL_WATCH = "vaultmesh.native-email.watch";
export const EmailCandidateSchema = z.object({ id: z.uuid(), code: z.string().regex(/^(?=.*\d)[A-Za-z0-9]{4,8}$/),
  sourceDomain: z.string().min(1).max(253), receivedAt: z.number().int().nonnegative(), expiresAt: z.number().int().nonnegative() }).strict();
export const EmailCandidatesSchema = z.object({ candidates: z.array(EmailCandidateSchema).max(20), boostExpiresAt: z.number().int().nonnegative().optional() }).strict();
export type EmailCandidate = z.infer<typeof EmailCandidateSchema>;
export const EmailPopupSchema = EmailCandidatesSchema.extend({ tabId: z.number().int().nonnegative(), url: z.string().url().max(8192) });
export type EmailPopup = z.infer<typeof EmailPopupSchema>;
export function clearEmail(value: unknown): void {
  if (value && typeof value === "object" && "candidates" in value && Array.isArray(value.candidates)) {
    for (const item of value.candidates) if (item && typeof item === "object") item.code = "";
  }
}
