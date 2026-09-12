import { z } from "zod";

export const RecoveryCodesSchema = z.object({ codes: z.array(z.string().min(1).max(256).refine((code) => code.trim().length > 0)).min(1).max(100) });
export type RecoveryCodes = z.infer<typeof RecoveryCodesSchema>;

// Projections of TrashItemSummary / LoginItemRevisionSummary, never historical detail.
export const LoginTrashSchema = z.array(z.object({
  trashId: z.string().uuid(), itemId: z.string().uuid(), title: z.string(), username: z.string(),
  deletedAt: z.number().int().nonnegative(),
}));
export const LoginHistorySchema = z.array(z.object({
  revisionId: z.string().uuid(), itemId: z.string().uuid(), title: z.string(), username: z.string(),
  savedAt: z.number().int().nonnegative(),
}));
export const LoginRecoveryCommandSchema = z.discriminatedUnion("operation", [
  z.object({ operation: z.literal("items.trash.restore"), trashId: z.string().uuid(), itemId: z.string().uuid() }).strict(),
  z.object({ operation: z.literal("items.trash.purge"), trashId: z.string().uuid() }).strict(),
  z.object({ operation: z.literal("items.trash.empty") }).strict(),
  z.object({ operation: z.literal("items.history.restore"), itemId: z.string().uuid(), revisionId: z.string().uuid() }).strict(),
  z.object({ operation: z.literal("items.history.clear"), id: z.string().uuid() }).strict(),
]);
export type LoginRecoveryCommand = z.infer<typeof LoginRecoveryCommandSchema>;
export type LoginTrash = z.infer<typeof LoginTrashSchema>;
export type LoginHistory = z.infer<typeof LoginHistorySchema>;
