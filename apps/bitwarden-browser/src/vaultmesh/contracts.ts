import { z } from "zod";
import { CONNECTION_CODES } from "./connection-diagnostics";
import { LoginSaveSchema } from "./login-contracts";
import { LoginRecoveryCommandSchema } from "./recovery-contracts";
import { ManagedCommandSchema } from "./managed-items";
import { SecurityCommandSchema } from "./security-tools";
import { PasskeyManagementSchema } from "./passkey-management";
import { GeneratedValueSchema } from "./vendor/browser-generated-value";

// These are projections of existing VaultMesh RPC results, not new broker operations.
export const VaultMeshStatusSchema = z.object({
  unlocked: z.boolean(),
  hasVault: z.boolean(),
  itemCount: z.number().int().nonnegative(),
});

// items.list returns LoginItemSummary (no kind/subtitle or protected values).
export const LoginSummarySchema = z.object({
  id: z.string().uuid(),
  title: z.string(),
  username: z.string(),
  url: z.string().nullable(),
  hasPassword: z.boolean(),
  hasTotpSecret: z.boolean(),
  hasRecoveryCodes: z.boolean(),
  autofillOnPageLoad: z.boolean(),
  masterPasswordReprompt: z.boolean(),
});
export const LoginSummariesSchema = z.array(LoginSummarySchema);
export type LoginSummary = z.infer<typeof LoginSummarySchema>;
export type VaultMeshStatus = z.infer<typeof VaultMeshStatusSchema>;

export const VAULTMESH_STATUS_MESSAGE = "vaultmesh.browser-status" as const;
export const SESSION_MESSAGE = "vaultmesh.browser-session" as const;
export const SESSION_INVALIDATED = "vaultmesh.browser-session-invalidated" as const;
export const FillFrameSchema = z.object({ frameId: z.number().int().nonnegative(), url: z.string().url().max(8192) }).strict();
export type FillFrame = z.infer<typeof FillFrameSchema>;
export const SessionMessageSchema = z.discriminatedUnion("action", [
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("generated-value"), command: z.enum(["copy", "insert"]), generated: GeneratedValueSchema, frame: FillFrameSchema.optional(),
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("item-fill"), itemKind: z.enum(["card", "identity", "ssh", "secret"]), id: z.string().uuid(), masterPassword: z.string().min(8).max(1024).optional(), frame: FillFrameSchema,
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("email-candidates") }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("email-fill"), candidateId: z.uuid(), tabId: z.number().int().nonnegative(), url: z.string().url().max(8192),
    mutationId: z.uuid(), expiresAt: z.iso.datetime(), sessionId: z.uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("passkey-management"), command: PasskeyManagementSchema,
    mutationId: z.uuid(), expiresAt: z.iso.datetime(), sessionId: z.uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("qr-authorize"),
    mutationId: z.uuid(), expiresAt: z.iso.datetime(), sessionId: z.uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("security-tool"), command: SecurityCommandSchema,
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("managed-item"), command: ManagedCommandSchema,
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("editor-open") }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("editor-context") }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("recovery-file-discard"), cleanupId: z.string().uuid() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("recovery-file-prepare"),
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("recovery-file-finish"), cleanupId: z.string().uuid(),
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("recovery-codes-view"), id: z.string().uuid(), masterPassword: z.string().min(8).max(1024),
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("recovery-code-copy"), id: z.string().uuid(), index: z.number().int().min(0).max(99), masterPassword: z.string().min(8).max(1024),
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("login-trash") }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("login-history"), id: z.string().uuid() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("login-recovery"), command: LoginRecoveryCommandSchema, confirmed: z.literal(true),
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("logins") }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("fill-context") }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("lock") }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("cancel-fill") }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("login-detail"), id: z.string().uuid() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("login-save"), mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative(), input: LoginSaveSchema, cleanupId: z.string().uuid().optional() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("login-delete"), mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative(), id: z.string().uuid(), confirmed: z.literal(true) }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("login-fill"), mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative(), id: z.string().uuid(), masterPassword: z.string().min(8).max(1_024).optional(), frame: FillFrameSchema.optional() }).strict(),
  z.object({ kind: z.literal(SESSION_MESSAGE), action: z.literal("login-copy"), field: z.enum(["username", "password", "totp"]),
    mutationId: z.string().uuid(), expiresAt: z.string().datetime(), sessionId: z.string().uuid(), revision: z.number().int().nonnegative(),
    id: z.string().uuid(), masterPassword: z.string().min(8).max(1024).optional() }).strict(),
  z.object({
    kind: z.literal(SESSION_MESSAGE), action: z.literal("unlock"),
    masterPassword: z.string().min(8).max(1_024),
  }).strict(),
]);

export const StatusResponseSchema = z.discriminatedUnion("status", [
  z.object({ kind: z.literal(VAULTMESH_STATUS_MESSAGE), status: z.literal("ready"), vault: VaultMeshStatusSchema.refine((v) => v.unlocked && v.hasVault), revision: z.number().int().nonnegative().optional(), sessionId: z.string().uuid().optional() }),
  z.object({ kind: z.literal(VAULTMESH_STATUS_MESSAGE), status: z.literal("locked"), vault: VaultMeshStatusSchema.refine((v) => !v.unlocked).optional(), revision: z.number().int().nonnegative().optional(), sessionId: z.string().uuid().optional() }),
  z.object({ kind: z.literal(VAULTMESH_STATUS_MESSAGE), status: z.literal("unpaired") }),
  z.object({ kind: z.literal(VAULTMESH_STATUS_MESSAGE), status: z.literal("unavailable"), code: z.enum(CONNECTION_CODES).optional() }),
]);

export const SessionResponseSchema = z.discriminatedUnion("ok", [
  z.object({ kind: z.literal(SESSION_MESSAGE), ok: z.literal(true), result: z.unknown() }),
  z.object({ kind: z.literal(SESSION_MESSAGE), ok: z.literal(false), code: z.string().max(128) }),
]);
