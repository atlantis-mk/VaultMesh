import { z } from 'zod';

/**
 * Renderer-neutral wire contract for the paired browser extension.  This is
 * deliberately separate from Electron IPC: browser requests are authenticated
 * by the native host/broker, never by a renderer sender check.
 */
export const BROWSER_RPC_VERSION = 2;
export const BROWSER_RPC_MAX_BYTES = 240 * 1024;

export const BrowserRpcOperationSchema = z.enum([
  'vault.status',
  'vault.workspace',
  'vault.create',
  'vault.unlock',
  'vault.unlock-history',
  'vault.lock',
  'vault.backup',
  'vault.restore',
  'vault.change-password',
  'biometric.status',
  'biometric.enable',
  'biometric.disable',
  'biometric.unlock',
  'pin.status',
  'pin.enable',
  'pin.disable',
  'pin.unlock',
  'security.settings.get',
  'security.settings.update',
  'events.poll',
  'browser.pairing.status',
  'browser.pairing.revoke',
  'browser.autofill.candidates',
  'browser.autofill.profile',
  'browser.autofill.execute',
  'browser.card.capture-status',
  'browser.login.password-changed',
  'browser.fill.record',
  'browser.fill.history',
  'browser.fill.request',
  'email.otp.watch',
  'email.otp.poll',
  'email.otp.candidates',
  'email.otp.fill',
  'passkeys.create',
  'passkeys.get',
  'confirmation.request',
  'items.list',
  'items.detail',
  'items.add',
  'items.update',
  'items.delete',
  'items.copy-username',
  'items.copy-password',
  'items.copy-totp',
  'items.recovery-codes',
  'items.copy-recovery-code',
  'items.recovery-codes.import-file', // phase input/results: browser-recovery-file.ts
  'items.trash.list',
  'items.trash.restore',
  'items.trash.purge',
  'items.trash.empty',
  'items.history.list',
  'items.history.restore',
  'items.history.clear',
  'cards.detail',
  'cards.add',
  'cards.update',
  'cards.delete',
  'cards.copy-number',
  'cards.copy-security-code',
  'cards.copy-pin',
  'cards.trash.list',
  'cards.trash.restore',
  'cards.trash.purge',
  'cards.trash.empty',
  'cards.history.list',
  'cards.history.restore',
  'cards.history.clear',
  'identities.detail',
  'identities.add',
  'identities.update',
  'identities.delete',
  'identities.trash.list',
  'identities.trash.restore',
  'identities.trash.purge',
  'identities.trash.empty',
  'identities.history.list',
  'identities.history.restore',
  'identities.history.clear',
  'ssh.detail',
  'ssh.add',
  'ssh.update',
  'ssh.delete',
  'ssh.copy-password',
  'ssh.copy-public-key',
  'ssh.copy-private-key',
  'ssh.copy-key-passphrase',
  'ssh.trash.list',
  'ssh.trash.restore',
  'ssh.trash.purge',
  'ssh.trash.empty',
  'ssh.history.list',
  'ssh.history.restore',
  'ssh.history.clear',
  'ssh.scan',
  'ssh.scan.commit',
  'ssh.scan.cancel',
  'secrets.list',
  'secrets.detail',
  'secrets.add',
  'secrets.update',
  'secrets.delete',
  'secrets.copy-value',
  'imports.select',
  'imports.commit',
  'imports.cancel',
  'password.generate',
  'cards.list',
  'identities.list',
  'ssh.list',
  'password.health',
]);

export type BrowserRpcOperation = z.infer<typeof BrowserRpcOperationSchema>;

export const BrowserRpcRequestSchema = z.object({
  kind: z.literal('vaultmesh.rpc'),
  version: z.literal(BROWSER_RPC_VERSION),
  requestId: z.uuid(),
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  operation: BrowserRpcOperationSchema,
  input: z.record(z.string(), z.unknown()).default({}),
}).strict();

export type BrowserRpcRequest = z.infer<typeof BrowserRpcRequestSchema>;

export const BrowserRpcErrorCodeSchema = z.enum([
  'desktop-unavailable',
  'unlock-required',
  'invalid-request',
  'request-expired',
  'request-replayed',
  'unsupported-operation',
  'update-required',
  'operation-failed',
  'cancelled',
  'confirmation-required',
  're-prompt-required',
]);

export type BrowserRpcErrorCode = z.infer<typeof BrowserRpcErrorCodeSchema>;

export type BrowserRpcResponse =
  | { kind: 'vaultmesh.rpc-result'; version: number; requestId: string; ok: true; result: unknown }
  | { kind: 'vaultmesh.rpc-result'; version: number; requestId: string; ok: false; error: { code: BrowserRpcErrorCode; message: string } };

export function browserRpcSuccess(requestId: string, result: unknown): BrowserRpcResponse {
  return { kind: 'vaultmesh.rpc-result', version: BROWSER_RPC_VERSION, requestId, ok: true, result };
}

export function browserRpcFailure(
  requestId: string,
  code: BrowserRpcErrorCode,
  message: string,
): BrowserRpcResponse {
  return { kind: 'vaultmesh.rpc-result', version: BROWSER_RPC_VERSION, requestId, ok: false, error: { code, message } };
}
