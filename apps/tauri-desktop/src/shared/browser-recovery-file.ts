import { z } from "zod";

// Existing operation, backwards-compatible empty input; transport metadata is separate.
export const BrowserRecoveryFileInputSchema = z.union([
  z.object({}).strict(),
  z.object({ phase: z.literal("prepare") }).strict(),
  z.object({ phase: z.literal("finish"), cleanupId: z.string().uuid() }).strict(),
]);
export const RecoveryFileCleanupSchema = z.object({ id: z.string().uuid(), expiresAt: z.number().int().positive() }).strict();
export const PreparedBrowserRecoveryFileSchema = z.object({
  codes: z.array(z.string().min(1).max(256).refine((code) => code.trim().length > 0)).min(1).max(100),
  fileName: z.string().min(1).max(1024),
  sourceFileStatus: z.literal("kept"),
  cleanup: RecoveryFileCleanupSchema,
}).strict();
export const FinishedBrowserRecoveryFileSchema = z.object({ sourceFileStatus: z.enum(["deleted", "kept", "failed"]) }).strict();
export type RecoveryFileCleanup = z.infer<typeof RecoveryFileCleanupSchema>;
export type PreparedBrowserRecoveryFile = z.infer<typeof PreparedBrowserRecoveryFileSchema>;

