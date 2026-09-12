import { BrowserRpcOperationSchema, type BrowserRpcOperation } from './browser-rpc';
import { BROWSER_RPC_POLICIES } from './browser-rpc-policy';

export type BrowserCapabilityClass = 'metadata' | 'mutation' | 'privileged-copy' | 'system-dialog' | 'page-disclosure';
export type BrowserExtensionRoute = 'popup:vault' | 'popup:generator' | 'popup:settings';

export type BrowserExtensionWorkflow = {
  id: string;
  route: BrowserExtensionRoute;
  commands: readonly BrowserRpcOperation[];
  requiresConfirmation: boolean;
};

/** Public desktop workflows mapped to real extension routes and exact RPC
 * commands. `events.poll` and `confirmation.request` are transport helpers,
 * not user-facing workflows, and are checked separately below. */
export const BROWSER_EXTENSION_WORKFLOWS: readonly BrowserExtensionWorkflow[] = [
  // login-management import-file includes prepare/finish in the independent editor;
  // finish is reachable only after a confirmed successful Login save.
  { id: 'vault-session', route: 'popup:vault', commands: ['vault.status', 'vault.workspace', 'vault.create', 'vault.unlock', 'vault.unlock-history', 'vault.lock'], requiresConfirmation: false },
  { id: 'login-management', route: 'popup:vault', commands: ['items.list', 'items.detail', 'items.add', 'items.update', 'items.delete', 'items.copy-username', 'items.copy-password', 'items.copy-totp', 'items.recovery-codes', 'items.copy-recovery-code', 'items.recovery-codes.import-file'], requiresConfirmation: true },
  { id: 'card-management', route: 'popup:vault', commands: ['cards.list', 'cards.detail', 'cards.add', 'cards.update', 'cards.delete', 'cards.copy-number', 'cards.copy-security-code', 'cards.copy-pin'], requiresConfirmation: true },
  { id: 'identity-management', route: 'popup:vault', commands: ['identities.list', 'identities.detail', 'identities.add', 'identities.update', 'identities.delete'], requiresConfirmation: true },
  { id: 'ssh-management', route: 'popup:vault', commands: ['ssh.list', 'ssh.detail', 'ssh.add', 'ssh.update', 'ssh.delete', 'ssh.copy-password', 'ssh.copy-public-key', 'ssh.copy-private-key', 'ssh.copy-key-passphrase'], requiresConfirmation: true },
  { id: 'secret-management', route: 'popup:vault', commands: ['secrets.list', 'secrets.detail', 'secrets.add', 'secrets.update', 'secrets.delete', 'secrets.copy-value'], requiresConfirmation: true },
  { id: 'login-recovery', route: 'popup:settings', commands: ['items.trash.list', 'items.trash.restore', 'items.trash.purge', 'items.trash.empty', 'items.history.list', 'items.history.restore', 'items.history.clear'], requiresConfirmation: true },
  { id: 'card-recovery', route: 'popup:settings', commands: ['cards.trash.list', 'cards.trash.restore', 'cards.trash.purge', 'cards.trash.empty', 'cards.history.list', 'cards.history.restore', 'cards.history.clear'], requiresConfirmation: true },
  { id: 'identity-recovery', route: 'popup:settings', commands: ['identities.trash.list', 'identities.trash.restore', 'identities.trash.purge', 'identities.trash.empty', 'identities.history.list', 'identities.history.restore', 'identities.history.clear'], requiresConfirmation: true },
  { id: 'ssh-recovery', route: 'popup:settings', commands: ['ssh.trash.list', 'ssh.trash.restore', 'ssh.trash.purge', 'ssh.trash.empty', 'ssh.history.list', 'ssh.history.restore', 'ssh.history.clear'], requiresConfirmation: true },
  { id: 'password-security', route: 'popup:settings', commands: ['password.generate', 'browser.generated.copy', 'password.health', 'security.settings.get', 'security.settings.update'], requiresConfirmation: false },
  { id: 'vault-lifecycle', route: 'popup:settings', commands: ['vault.backup', 'vault.restore', 'vault.change-password'], requiresConfirmation: true },
  { id: 'biometrics', route: 'popup:settings', commands: ['biometric.status', 'biometric.enable', 'biometric.disable', 'biometric.unlock'], requiresConfirmation: false },
  { id: 'pin-unlock', route: 'popup:settings', commands: ['pin.status', 'pin.enable', 'pin.disable', 'pin.unlock'], requiresConfirmation: false },
  { id: 'browser-pairing', route: 'popup:settings', commands: ['browser.pairing.status', 'browser.pairing.revoke'], requiresConfirmation: true },
  { id: 'imports', route: 'popup:settings', commands: ['imports.select', 'imports.commit', 'imports.cancel'], requiresConfirmation: true },
  { id: 'ssh-key-scan', route: 'popup:settings', commands: ['ssh.scan', 'ssh.scan.commit', 'ssh.scan.cancel'], requiresConfirmation: true },
  // The experimental Bitwarden popup uses the same execute/audit workflow with a bounded nativeLoginPlan.
  { id: 'browser-autofill', route: 'popup:vault', commands: ['browser.autofill.candidates', 'browser.autofill.profile', 'browser.autofill.execute', 'browser.card.capture-status', 'browser.login.password-changed', 'browser.fill.record', 'browser.fill.history', 'browser.fill.request'], requiresConfirmation: true },
  { id: 'email-otp', route: 'popup:vault', commands: ['email.otp.watch', 'email.otp.poll', 'email.otp.candidates', 'email.otp.fill'], requiresConfirmation: false },
  { id: 'passkeys', route: 'popup:vault', commands: ['passkeys.create', 'passkeys.get'], requiresConfirmation: false },
];

const INFRASTRUCTURE_OPERATIONS = new Set<BrowserRpcOperation>(['events.poll', 'confirmation.request']);

export function assertBrowserExtensionWorkflowManifest(workflows = BROWSER_EXTENSION_WORKFLOWS): void {
  const ids = new Set<string>();
  const commands = new Set<BrowserRpcOperation>();
  const routes = new Set<BrowserExtensionRoute>(['popup:vault', 'popup:generator', 'popup:settings']);
  for (const workflow of workflows) {
    if (!workflow.id || ids.has(workflow.id) || !routes.has(workflow.route) || workflow.commands.length === 0) throw new Error('浏览器扩展功能清单包含重复或无效条目。');
    ids.add(workflow.id);
    for (const command of workflow.commands) {
      if (commands.has(command) || !(command in BROWSER_RPC_POLICIES)) throw new Error(`浏览器扩展命令未注册或重复：${command}`);
      commands.add(command);
    }
  }
  const missing = BrowserRpcOperationSchema.options.filter((operation) => !INFRASTRUCTURE_OPERATIONS.has(operation) && !commands.has(operation));
  if (missing.length) throw new Error(`浏览器扩展未覆盖桌面命令：${missing.join(', ')}`);
}
