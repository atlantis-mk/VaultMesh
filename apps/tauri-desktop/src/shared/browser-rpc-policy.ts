import type { BrowserRpcOperation, BrowserRpcRequest } from './browser-rpc';

export type BrowserRpcCapability = 'metadata' | 'mutation' | 'privileged-copy' | 'system-dialog' | 'page-disclosure';
export type BrowserRpcPolicy = {
  capability: BrowserRpcCapability;
  requiresUnlock: boolean;
  requiresGesture: boolean;
  requiresConfirmation: boolean;
};

const metadata = (requiresUnlock = true): BrowserRpcPolicy => ({ capability: 'metadata', requiresUnlock, requiresGesture: false, requiresConfirmation: false });
const mutation = (requiresConfirmation = false): BrowserRpcPolicy => ({ capability: 'mutation', requiresUnlock: true, requiresGesture: true, requiresConfirmation });
const mutationWhileLocked = (requiresConfirmation = false): BrowserRpcPolicy => ({ capability: 'mutation', requiresUnlock: false, requiresGesture: true, requiresConfirmation });
const copy: BrowserRpcPolicy = { capability: 'privileged-copy', requiresUnlock: true, requiresGesture: true, requiresConfirmation: false };
const systemDialog = (requiresUnlock: boolean, requiresConfirmation = false): BrowserRpcPolicy => ({ capability: 'system-dialog', requiresUnlock, requiresGesture: true, requiresConfirmation });
const pageDisclosure: BrowserRpcPolicy = { capability: 'page-disclosure', requiresUnlock: true, requiresGesture: true, requiresConfirmation: false };
const automaticPageDisclosure: BrowserRpcPolicy = { capability: 'page-disclosure', requiresUnlock: true, requiresGesture: false, requiresConfirmation: false };
const automaticAudit: BrowserRpcPolicy = { capability: 'mutation', requiresUnlock: true, requiresGesture: false, requiresConfirmation: false };

export const BROWSER_RPC_POLICIES: Record<BrowserRpcOperation, BrowserRpcPolicy> = {
  'vault.status': metadata(false),
  'vault.workspace': metadata(),
  'vault.create': mutationWhileLocked(true),
  'vault.unlock': mutationWhileLocked(),
  'vault.unlock-history': metadata(false),
  'vault.lock': mutation(),
  'vault.backup': systemDialog(true, true),
  'vault.restore': systemDialog(true, true),
  'vault.change-password': mutation(true),
  'biometric.status': metadata(false),
  'biometric.enable': systemDialog(true),
  'biometric.disable': mutation(),
  'biometric.unlock': systemDialog(false),
  'pin.status': metadata(false),
  'pin.enable': mutation(),
  'pin.disable': mutation(),
  'pin.unlock': mutationWhileLocked(),
  'security.settings.get': metadata(),
  'security.settings.update': mutation(),
  'events.poll': metadata(false),
  'browser.pairing.status': metadata(false),
  'browser.pairing.revoke': systemDialog(false, true),
  'browser.autofill.candidates': metadata(),
  'browser.autofill.profile': metadata(),
  'browser.autofill.execute': automaticPageDisclosure,
  'browser.card.capture-status': automaticPageDisclosure,
  'browser.login.password-changed': automaticPageDisclosure,
  'browser.fill.record': automaticAudit,
  'browser.fill.history': metadata(),
  'browser.fill.request': pageDisclosure,
  'email.otp.watch': mutation(),
  'email.otp.poll': automaticAudit,
  'email.otp.candidates': metadata(),
  'email.otp.fill': pageDisclosure,
  // Chrome has already applied the WebAuthn origin, RP-ID, focus, timeout and
  // user-activation checks before raising a proxy event. These routes are only
  // callable through the authenticated native channel and never disclose key
  // material to the extension.
  'passkeys.create': automaticAudit,
  'passkeys.get': automaticPageDisclosure,
  // The target policy is checked when the token is created. This helper must
  // remain callable while locked so `vault.create` can obtain its required
  // confirmation without opening unrelated locked operations.
  'confirmation.request': mutationWhileLocked(),
  'items.list': metadata(),
  // Login custom-field values are protected. Keep the established RPC shape,
  // but require an explicit fresh gesture so this is a bounded privileged
  // read rather than ordinary renderer-safe metadata.
  'items.detail': pageDisclosure,
  'items.add': mutation(),
  'items.update': mutation(),
  'items.delete': mutation(true),
  'items.copy-username': copy,
  'items.copy-password': copy,
  'items.copy-totp': copy,
  'items.recovery-codes': pageDisclosure,
  'items.copy-recovery-code': copy,
  'items.recovery-codes.import-file': systemDialog(true, true), // both prepare and finish require fresh confirmation
  'items.trash.list': metadata(),
  'items.trash.restore': mutation(),
  'items.trash.purge': mutation(true),
  'items.trash.empty': mutation(true),
  'items.history.list': metadata(),
  'items.history.restore': mutation(true),
  'items.history.clear': mutation(true),
  'cards.list': metadata(),
  'cards.detail': metadata(),
  'cards.add': mutation(),
  'cards.update': mutation(),
  'cards.delete': mutation(true),
  'cards.copy-number': copy,
  'cards.copy-security-code': copy,
  'cards.copy-pin': copy,
  'cards.trash.list': metadata(),
  'cards.trash.restore': mutation(),
  'cards.trash.purge': mutation(true),
  'cards.trash.empty': mutation(true),
  'cards.history.list': metadata(),
  'cards.history.restore': mutation(true),
  'cards.history.clear': mutation(true),
  'identities.list': metadata(),
  'identities.detail': metadata(),
  'identities.add': mutation(),
  'identities.update': mutation(),
  'identities.delete': mutation(true),
  'identities.trash.list': metadata(),
  'identities.trash.restore': mutation(),
  'identities.trash.purge': mutation(true),
  'identities.trash.empty': mutation(true),
  'identities.history.list': metadata(),
  'identities.history.restore': mutation(true),
  'identities.history.clear': mutation(true),
  'ssh.list': metadata(),
  'ssh.detail': metadata(),
  'ssh.add': mutation(),
  'ssh.update': mutation(),
  'ssh.delete': mutation(true),
  'ssh.copy-password': copy,
  'ssh.copy-public-key': copy,
  'ssh.copy-private-key': copy,
  'ssh.copy-key-passphrase': copy,
  'ssh.trash.list': metadata(),
  'ssh.trash.restore': mutation(),
  'ssh.trash.purge': mutation(true),
  'ssh.trash.empty': mutation(true),
  'ssh.history.list': metadata(),
  'ssh.history.restore': mutation(true),
  'ssh.history.clear': mutation(true),
  'ssh.scan': systemDialog(true),
  'ssh.scan.commit': mutation(true),
  'ssh.scan.cancel': mutation(),
  'secrets.list': metadata(),
  'secrets.detail': metadata(),
  'secrets.add': mutation(),
  'secrets.update': mutation(),
  'secrets.delete': mutation(true),
  'secrets.copy-value': copy,
  'imports.select': systemDialog(true),
  'imports.commit': mutation(true),
  'imports.cancel': mutation(),
  'password.generate': copy,
  'password.health': metadata(),
};

export type BrowserRpcAuthorization =
  | { authorized: true }
  | { authorized: false; code: 'unlock-required' | 'invalid-request'; message: string };

export function authorizeBrowserRpc(request: BrowserRpcRequest, unlocked: boolean): BrowserRpcAuthorization {
  const policy = BROWSER_RPC_POLICIES[request.operation];
  if (policy.requiresUnlock && !unlocked) {
    return { authorized: false, code: 'unlock-required', message: '请先在 VaultMesh 插件中单独解锁。' };
  }
  if (policy.requiresGesture || (request.operation === 'browser.autofill.execute' && (request.input.nativeItemPlan !== undefined || request.input.nativeLoginPlan !== undefined && request.input.mode !== 'automatic'))) {
    const gestureId = request.input.userGestureId;
    if (typeof gestureId !== 'string' || !/^[0-9a-f-]{36}$/i.test(gestureId)) {
      return { authorized: false, code: 'invalid-request', message: '该操作需要新的用户手势。' };
    }
  }
  return { authorized: true };
}
