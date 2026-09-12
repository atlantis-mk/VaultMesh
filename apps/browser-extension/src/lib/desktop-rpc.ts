import { z } from "zod";

import { persistentNativeConnection, type NativeRpcRequest } from "@/lib/native-connection";
import { EmailOtpCandidateSchema } from "@/lib/protocol";

const VERSION = 2;
const MAX_REQUEST_LIFETIME_MS = 60_000;

const statusSchema = z.object({ unlocked: z.boolean(), hasVault: z.boolean(), itemCount: z.number().int().nonnegative() });
const unlockEventSchema = z.object({ eventId: z.string().uuid(), occurredAt: z.number().int().nonnegative(), source: z.enum(['desktop', 'desktop-pin', 'extension-master-password', 'extension-biometric', 'extension-pin']) });
const fillEventSchema = z.object({ eventId: z.string().uuid(), occurredAt: z.number().int().nonnegative(), itemKind: z.enum(['login', 'card', 'identity', 'secret', 'ssh']), itemId: z.string().uuid(), itemTitle: z.string(), origin: z.string(), fieldCount: z.number().int().positive() });
const loginSchema = z.object({ id: z.string().uuid(), title: z.string(), username: z.string(), url: z.string().nullable(), notes: z.string().nullable(), hasPassword: z.boolean(), hasTotpSecret: z.boolean(), hasRecoveryCodes: z.boolean().default(false), autofillOnPageLoad: z.boolean(), masterPasswordReprompt: z.boolean() });
const loginDetailSchema = loginSchema.omit({ hasPassword: true }).extend({ folder: z.string().nullable(), favorite: z.boolean(), additionalUrls: z.array(z.string()), customFields: z.array(z.object({ label: z.string(), value: z.string() })) });
const recoveryCodesSchema = z.object({ codes: z.array(z.string().min(1).max(256)).min(1).max(100) });
const recoveryCodeFileResultSchema = z.object({ codes: z.array(z.string().min(1).max(256)).min(1).max(100), fileName: z.string().min(1).max(1_024), sourceFileStatus: z.enum(['deleted', 'kept', 'failed']) });
const clipboardResultSchema = z.object({ clearsAt: z.number().int().nonnegative() });
const emailOtpCandidatesSchema = z.object({
  candidates: z.array(EmailOtpCandidateSchema).max(20),
  boostExpiresAt: z.number().int().nonnegative(),
});
const cardSchema = z.object({ id: z.string().uuid(), title: z.string(), cardholderName: z.string(), maskedNumber: z.string(), expirationMonth: z.number().int(), expirationYear: z.number().int(), hasSecurityCode: z.boolean(), hasPin: z.boolean(), issuer: z.string().nullable(), network: z.string().nullable(), notes: z.string().nullable(), masterPasswordReprompt: z.boolean() });
const cardDetailSchema = cardSchema.extend({ billingAddress: z.string().nullable(), folder: z.string().nullable(), favorite: z.boolean() });
const identitySchema = z.object({ id: z.string().uuid(), title: z.string(), displayName: z.string().nullable(), organization: z.string().nullable(), folder: z.string().nullable(), favorite: z.boolean() });
const identityValueSchema = z.object({ id: z.string().uuid(), label: z.string(), value: z.string(), preferred: z.boolean() });
const postalAddressSchema = z.object({ id: z.string().uuid(), label: z.string(), addressLine1: z.string(), addressLine2: z.string().nullable(), city: z.string().nullable(), region: z.string().nullable(), postalCode: z.string().nullable(), countryCode: z.string().nullable(), country: z.string().nullable(), preferred: z.boolean() });
const identityDetailSchema = z.object({
  id: z.string().uuid(), title: z.string(), firstName: z.string().nullable(), middleName: z.string().nullable(), lastName: z.string().nullable(), birthDate: z.string().nullable(),
  emails: z.array(identityValueSchema), phones: z.array(identityValueSchema), addresses: z.array(postalAddressSchema),
  organization: z.string().nullable(), department: z.string().nullable(), jobTitle: z.string().nullable(), website: z.string().nullable(), notes: z.string().nullable(), folder: z.string().nullable(), favorite: z.boolean(),
});
const sshSchema = z.object({ id: z.string().uuid(), title: z.string(), host: z.string().nullable(), port: z.number().int(), username: z.string(), hasPassword: z.boolean(), hasPublicKey: z.boolean(), hasPrivateKey: z.boolean(), hasKeyPassphrase: z.boolean(), keyAlgorithm: z.string().nullable(), publicKeyFingerprint: z.string().nullable(), notes: z.string().nullable(), masterPasswordReprompt: z.boolean() });
const sshDetailSchema = sshSchema.extend({ folder: z.string().nullable(), favorite: z.boolean() });
const secretSchema = z.object({ id: z.string().uuid(), title: z.string(), kind: z.enum(["api-key", "access-token", "authenticator-key", "client-secret", "webhook-secret", "database-credential", "recovery-codes", "certificate", "software-license", "identity-document", "secure-note", "crypto-wallet", "other"]), provider: z.string().nullable(), account: z.string().nullable(), environment: z.string().nullable(), expiresAt: z.string().nullable(), website: z.string().nullable(), notes: z.string().nullable(), favorite: z.boolean(), masterPasswordReprompt: z.boolean(), isPasskey: z.boolean().default(false), loginId: z.string().uuid().nullable().default(null) });
const secretDetailSchema = secretSchema.extend({ scopes: z.array(z.string()), folder: z.string().nullable() });

export const workspaceSchema = z.object({
  status: statusSchema,
  items: z.array(loginSchema),
  cards: z.array(cardSchema),
  identities: z.array(identitySchema),
  sshCredentials: z.array(sshSchema),
  secrets: z.array(secretSchema).default([]),
});

export type WorkspaceSnapshot = z.infer<typeof workspaceSchema>;
export type UnlockEvent = z.infer<typeof unlockEventSchema>;
export type FillEvent = z.infer<typeof fillEventSchema>;
export type DesktopState = "ready" | "locked" | "unavailable" | "error";
export type LoginDetail = z.infer<typeof loginDetailSchema>;
export type RecoveryCodeFileResult = z.infer<typeof recoveryCodeFileResultSchema>;
export type PasskeySummary = z.infer<typeof secretSchema>;
export type EmailOtpCandidate = z.infer<typeof EmailOtpCandidateSchema>;
export type EmailOtpCandidates = z.infer<typeof emailOtpCandidatesSchema>;

const responseSchema = z.discriminatedUnion("ok", [
  z.object({ kind: z.literal("vaultmesh.rpc-result"), version: z.literal(VERSION), requestId: z.string().uuid(), ok: z.literal(true), result: z.unknown() }),
  z.object({ kind: z.literal("vaultmesh.rpc-result"), version: z.literal(VERSION), requestId: z.string().uuid(), ok: z.literal(false), error: z.object({ code: z.string(), message: z.string() }) }),
]);
const hostStatusSchema = z.object({
  kind: z.literal("vaultmesh.host-status"),
  status: z.string(),
  requestId: z.string().uuid().optional(),
});

export class DesktopRpcError extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}

export type Operation =
  | "vault.status" | "vault.workspace" | "vault.create" | "vault.unlock" | "vault.unlock-history" | "vault.lock" | "vault.backup" | "vault.restore" | "vault.change-password"
  | "biometric.status" | "biometric.enable" | "biometric.disable" | "biometric.unlock" | "pin.status" | "pin.enable" | "pin.disable" | "pin.unlock" | "security.settings.get" | "security.settings.update"
  | "events.poll" | "browser.pairing.status" | "browser.pairing.revoke" | "confirmation.request"
  | "browser.autofill.candidates" | "browser.autofill.profile" | "browser.autofill.execute" | "browser.card.capture-status" | "browser.login.password-changed" | "browser.fill.record" | "browser.fill.history" | "browser.fill.request"
  | "email.otp.watch" | "email.otp.poll" | "email.otp.candidates" | "email.otp.fill"
  | "passkeys.create" | "passkeys.get"
  | "items.list" | "items.detail" | "items.add" | "items.update" | "items.delete" | "items.copy-username" | "items.copy-password" | "items.copy-totp" | "items.recovery-codes" | "items.copy-recovery-code" | "items.recovery-codes.import-file" | "items.trash.list" | "items.trash.restore" | "items.trash.purge" | "items.trash.empty" | "items.history.list" | "items.history.restore" | "items.history.clear"
  | "cards.list" | "cards.detail" | "cards.add" | "cards.update" | "cards.delete" | "cards.copy-number" | "cards.copy-security-code" | "cards.copy-pin" | "cards.trash.list" | "cards.trash.restore" | "cards.trash.purge" | "cards.trash.empty" | "cards.history.list" | "cards.history.restore" | "cards.history.clear"
  | "identities.list" | "identities.detail" | "identities.add" | "identities.update" | "identities.delete" | "identities.trash.list" | "identities.trash.restore" | "identities.trash.purge" | "identities.trash.empty" | "identities.history.list" | "identities.history.restore" | "identities.history.clear"
  | "ssh.list" | "ssh.detail" | "ssh.add" | "ssh.update" | "ssh.delete" | "ssh.copy-password" | "ssh.copy-public-key" | "ssh.copy-private-key" | "ssh.copy-key-passphrase" | "ssh.trash.list" | "ssh.trash.restore" | "ssh.trash.purge" | "ssh.trash.empty" | "ssh.history.list" | "ssh.history.restore" | "ssh.history.clear" | "ssh.scan" | "ssh.scan.commit" | "ssh.scan.cancel"
  | "secrets.list" | "secrets.detail" | "secrets.add" | "secrets.update" | "secrets.delete" | "secrets.copy-value"
  | "imports.select" | "imports.commit" | "imports.cancel" | "password.generate" | "password.health";

const NO_GESTURE_OPERATIONS = new Set<Operation>(["vault.status", "vault.workspace", "vault.unlock-history", "biometric.status", "pin.status", "security.settings.get", "events.poll", "browser.pairing.status", "browser.autofill.candidates", "browser.autofill.profile", "browser.autofill.execute", "browser.card.capture-status", "browser.login.password-changed", "browser.fill.record", "browser.fill.history", "email.otp.poll", "email.otp.candidates", "passkeys.create", "passkeys.get", "items.list", "items.trash.list", "items.history.list", "cards.list", "cards.detail", "cards.trash.list", "cards.history.list", "identities.list", "identities.detail", "identities.trash.list", "identities.history.list", "ssh.list", "ssh.detail", "ssh.trash.list", "ssh.history.list", "secrets.list", "secrets.detail", "password.health"]);

export async function desktopRpc(operation: Operation, input: Record<string, unknown> = {}, userGestureId?: string): Promise<unknown> {
  const request = createRequest(operation, input, userGestureId);
  return parseResponse(request, sendThroughBackground(request));
}

/** Background-only entry point used by fill commands without routing a
 * message back into the same service worker. */
export async function backgroundDesktopRpc(operation: Operation, input: Record<string, unknown> = {}, userGestureId?: string): Promise<unknown> {
  const request = createRequest(operation, input, userGestureId);
  return parseResponse(request, persistentNativeConnection.request(request));
}

export type DesktopRpcRuntimeMessage = { kind: "vaultmesh.desktop-rpc"; request: NativeRpcRequest };

export function isDesktopRpcRuntimeMessage(value: unknown): value is DesktopRpcRuntimeMessage {
  if (!value || typeof value !== "object") return false;
  const candidate = value as { kind?: unknown; request?: Partial<NativeRpcRequest> };
  return candidate.kind === "vaultmesh.desktop-rpc"
    && candidate.request?.kind === "vaultmesh.rpc"
    && candidate.request.version === VERSION
    && typeof candidate.request.requestId === "string";
}

function createRequest(operation: Operation, input: Record<string, unknown>, userGestureId?: string): NativeRpcRequest {
  const requestId = crypto.randomUUID();
  const now = new Date();
  return {
    kind: "vaultmesh.rpc",
    version: VERSION,
    requestId,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + MAX_REQUEST_LIFETIME_MS).toISOString(),
    operation,
    input: NO_GESTURE_OPERATIONS.has(operation) ? input : { ...input, userGestureId: userGestureId ?? crypto.randomUUID() },
  };
}

async function sendThroughBackground(request: NativeRpcRequest): Promise<unknown> {
  return browser.runtime.sendMessage({ kind: "vaultmesh.desktop-rpc", request } satisfies DesktopRpcRuntimeMessage);
}

async function parseResponse(request: NativeRpcRequest, pendingResponse: Promise<unknown>): Promise<unknown> {
  let response: unknown;
  try {
    response = await pendingResponse;
  } catch {
    throw new DesktopRpcError("desktop-unavailable", "无法连接 VaultMesh 桌面端。");
  }
  const hostStatus = hostStatusSchema.safeParse(response);
  if (hostStatus.success) {
    const code = hostStatus.data.status;
    const message = code === "unpaired"
      ? "VaultMesh 插件尚未与桌面端配对。"
      : code === "unlock-required"
        ? "VaultMesh 插件已锁定，请在插件中单独解锁。"
        : "无法连接 VaultMesh 桌面端。";
    throw new DesktopRpcError(code, message);
  }
  const parsed = responseSchema.safeParse(response);
  if (!parsed.success || parsed.data.requestId !== request.requestId) throw new DesktopRpcError("desktop-unavailable", "无法连接 VaultMesh 桌面端。");
  if (!parsed.data.ok) throw new DesktopRpcError(parsed.data.error.code, parsed.data.error.message);
  return parsed.data.result;
}

export async function getDesktopStatus(): Promise<z.infer<typeof statusSchema>> {
  return statusSchema.parse(await desktopRpc("vault.status"));
}

export async function getUnlockHistory(): Promise<UnlockEvent[]> {
  return z.array(unlockEventSchema).parse(await desktopRpc("vault.unlock-history"));
}

export async function getFillHistory(): Promise<FillEvent[]> {
  return z.array(fillEventSchema).parse(await desktopRpc("browser.fill.history"));
}

export async function getEmailOtpCandidates(topOrigin: string): Promise<EmailOtpCandidates> {
  return emailOtpCandidatesSchema.parse(await desktopRpc("email.otp.candidates", { topOrigin }));
}

export async function getWorkspaceSnapshot(): Promise<WorkspaceSnapshot> {
  return workspaceSchema.parse(await desktopRpc("vault.workspace"));
}
export async function pollDesktopEvents(after: number) {
  return z.object({ sequence: z.number().int().nonnegative(), events: z.array(z.object({ sequence: z.number().int(), type: z.enum(["vault-locked", "pairing-revoked", "operation-expired", "desktop-shutdown"]), occurredAt: z.string() })) }).parse(await desktopRpc("events.poll", { after }));
}

export async function getLoginDetail(id: string): Promise<LoginDetail> { return loginDetailSchema.parse(await desktopRpc("items.detail", { id })); }
export async function getRecoveryCodes(id: string, masterPassword: string): Promise<string[]> {
  return recoveryCodesSchema.parse(await desktopRpc("items.recovery-codes", { id, masterPassword })).codes;
}
export async function copyRecoveryCode(id: string, index: number, masterPassword: string): Promise<number> {
  return clipboardResultSchema.parse(await desktopRpc("items.copy-recovery-code", { id, index, masterPassword })).clearsAt;
}
export async function importRecoveryCodesFile(): Promise<RecoveryCodeFileResult | null> {
  try {
    return recoveryCodeFileResultSchema.parse(await confirmedDesktopRpc("items.recovery-codes.import-file", {}));
  } catch (cause) {
    if (cause instanceof DesktopRpcError && cause.code === "cancelled") return null;
    throw cause;
  }
}
export async function getPasskeysForLogin(loginId: string): Promise<PasskeySummary[]> {
  return z.array(secretSchema).parse(await desktopRpc("secrets.list")).filter((secret) => secret.isPasskey && secret.loginId === loginId);
}
export async function deletePasskey(id: string): Promise<void> { await confirmedDesktopRpc("secrets.delete", { id }); }
export async function saveLogin(input: Record<string, unknown>): Promise<void> {
  if (typeof input.id === "string") await desktopRpc("items.update", input);
  else await desktopRpc("items.add", input);
}
export async function deleteLogin(id: string): Promise<void> {
  await confirmedDesktopRpc("items.delete", { id });
}
export async function copyLoginUsername(id: string): Promise<number> { return z.object({ clearsAt: z.number() }).parse(await desktopRpc("items.copy-username", { id })).clearsAt; }
export async function copyLoginPassword(id: string, masterPassword?: string): Promise<number> { return z.object({ clearsAt: z.number() }).parse(await desktopRpc("items.copy-password", { id, masterPassword: masterPassword ?? null })).clearsAt; }
export async function getCardDetail(id: string) { return cardDetailSchema.parse(await desktopRpc("cards.detail", { id })); }
export async function saveCard(input: Record<string, unknown>) { await desktopRpc(typeof input.id === "string" ? "cards.update" : "cards.add", input); }
export async function deleteCard(id: string) { await confirmedDesktopRpc("cards.delete", { id }); }
export async function copyCardNumber(id: string, masterPassword?: string) { return z.object({ clearsAt: z.number() }).parse(await desktopRpc("cards.copy-number", { id, masterPassword: masterPassword ?? null })).clearsAt; }
export async function getSecretDetail(id: string) { return secretDetailSchema.parse(await desktopRpc("secrets.detail", { id })); }
export async function saveSecret(input: Record<string, unknown>) { await desktopRpc(typeof input.id === "string" ? "secrets.update" : "secrets.add", input); }
export async function getIdentityDetail(id: string) { return identityDetailSchema.parse(await desktopRpc("identities.detail", { id })); }
export async function getSshDetail(id: string) { return sshDetailSchema.parse(await desktopRpc("ssh.detail", { id })); }

export async function confirmedDesktopRpc(operation: Operation, input: Record<string, unknown>): Promise<unknown> {
  const userGestureId = crypto.randomUUID();
  const confirmation = z.object({ confirmationToken: z.string().uuid() }).parse(await desktopRpc("confirmation.request", { operation }, userGestureId));
  return desktopRpc(operation, { ...input, confirmationToken: confirmation.confirmationToken }, userGestureId);
}
