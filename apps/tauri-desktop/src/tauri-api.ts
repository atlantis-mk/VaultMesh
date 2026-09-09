import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

import type { VaultMeshApi } from './shared/api';

const call = async <T>(operation: string, input: unknown = {}): Promise<T> => {
  try {
    return await invoke<T>('desktop_invoke', { request: { operation, input } });
  } catch (reason) {
    if (reason instanceof Error) throw reason;
    if (typeof reason === 'string' && reason.length > 0) throw new Error(reason);
    throw new Error('操作失败。');
  }
};

const copy = (operation: string, id: string, masterPassword?: string) =>
  call<{ clearsAt: number }>(operation, { id, masterPassword: masterPassword ?? null });

export function createTauriVaultMeshApi(): VaultMeshApi {
  return {
    desktop: {
      startupSettings: () => call('desktop.startup.get'),
      updateStartupSettings: (input) => call('desktop.startup.update', input),
      browserIntegrationStatus: () => call('desktop.browser-integration.get'),
      retryBrowserIntegration: () => call('desktop.browser-integration.retry'),
    },
    vault: {
      create: (input) => call('vault.create', input),
      unlock: (input) => call('vault.unlock', input),
      lock: () => call('vault.lock'),
      status: () => call('vault.status'),
      unlockHistory: () => call('vault.unlock-history'),
      backup: () => call('vault.backup'),
      restore: (input) => call('vault.restore', input),
      changeMasterPassword: (input) => call('vault.change-password', input),
      biometricStatus: () => call('biometric.status'),
      enableBiometric: () => call('biometric.enable'),
      disableBiometric: () => call('biometric.disable'),
      unlockWithBiometrics: () => call('biometric.unlock'),
      pinStatus: () => call('pin.status'),
      enablePin: (input) => call('pin.enable', input),
      disablePin: () => call('pin.disable'),
      unlockWithPin: (input) => call('pin.unlock', input),
      onLocked: (callback) => {
        let active = true;
        let unlisten: (() => void) | undefined;
        void listen('vault-locked', () => callback()).then((next) => {
          if (active) unlisten = next;
          else next();
        });
        return () => { active = false; unlisten?.(); };
      },
    },
    security: {
      settings: () => call('security.settings.get'),
      updateSettings: (input) => call('security.settings.update', input),
    },
    lan: {
      status: () => call('lan.pairing.status'),
      startDiscovery: () => call('lan.discovery.start'),
      stopDiscovery: () => call('lan.discovery.stop'),
      scan: () => call('lan.discovery.scan'),
      listTrusted: () => call('lan.pairing.list'),
      begin: (pairingRef, pairingCode) => call('lan.pairing.begin', { pairingRef, pairingCode }),
      revoke: (pairingRef) => call('lan.pairing.revoke', { pairingRef }),
      rename: (pairingRef, label) => call('lan.pairing.rename', { pairingRef, label }),
    },
    agent: {
      status: () => call('agent.status'),
      enablePin: (input) => call('agent.pin.enable', input),
      disablePin: () => call('agent.pin.disable'),
      lockAllAccess: () => call('agent.access.lock-all'),
      lockClientAccess: (clientId) => call('agent.access.lock-client', { clientId }),
      updateAccessSettings: (input) => call('agent.access.settings.update', input),
      activateAction: (permissionRef, choice) => call('agent.permission.action.resolve', { permissionRef, choice }),
      approveConfirmation: (confirmationRef) => call('agent.confirmation.approve', { confirmationRef }),
      rejectConfirmation: (confirmationRef) => call('agent.confirmation.reject', { confirmationRef }),
      resolvePermission: (permissionRef, choice) => call('agent.permission.resolve', { permissionRef, choice }),
      resetAuthorizationRule: (ruleId) => call('agent.authorization.rule.delete', { ruleId }),
      clearAudit: () => call('agent.audit.clear'),
      revokeClient: (clientId) => call('agent.client.revoke', { clientId }),
      onPairingRequested: (callback) => {
        let active = true;
        let unlisten: (() => void) | undefined;
        void listen('agent-pairing-requested', () => callback()).then((next) => {
          if (active) unlisten = next;
          else next();
        });
        return () => { active = false; unlisten?.(); };
      },
    },
    items: {
      list: () => call('items.list'), detail: (id) => call('items.detail', { id }),
      add: (input) => call('items.add', input), update: (input) => call('items.update', input),
      delete: (id) => call('items.delete', { id }),
      copyUsername: (id) => copy('items.copy-username', id),
      copyPassword: (id, password) => copy('items.copy-password', id, password),
      revealPassword: (id, password) => call('items.reveal-password', { id, masterPassword: password ?? null }),
      totpCode: (id, password) => call('items.totp-code', { id, masterPassword: password ?? null }),
      copyTotp: (id, password) => copy('items.copy-totp', id, password),
      recoveryCodes: (id, masterPassword) => call('items.recovery-codes', { id, masterPassword }),
      copyRecoveryCode: (id, index, masterPassword) => call('items.copy-recovery-code', { id, index, masterPassword }),
      importRecoveryCodesFile: () => call('items.recovery-codes.import-file'),
      autofillCandidates: (url) => call('browser.autofill.candidates', { url }),
      trash: () => call('items.trash.list'), restoreTrash: (trashId) => call('items.trash.restore', { trashId }),
      purgeTrash: (trashId) => call('items.trash.purge', { trashId }), emptyTrash: () => call('items.trash.empty'),
      history: (id) => call('items.history.list', { id }),
      restoreRevision: (itemId, revisionId) => call('items.history.restore', { itemId, revisionId }),
      clearHistory: (id) => call('items.history.clear', { id }), passwordHealth: () => call('password.health'),
    },
    cards: {
      list: () => call('cards.list'), detail: (id) => call('cards.detail', { id }),
      add: (input) => call('cards.add', input), update: (input) => call('cards.update', input),
      delete: (id) => call('cards.delete', { id }), copyNumber: (id, password) => copy('cards.copy-number', id, password),
      copySecurityCode: (id, password) => copy('cards.copy-security-code', id, password),
      copyPin: (id, password) => copy('cards.copy-pin', id, password),
      trash: () => call('cards.trash.list'), restoreTrash: (trashId) => call('cards.trash.restore', { trashId }),
      purgeTrash: (trashId) => call('cards.trash.purge', { trashId }), emptyTrash: () => call('cards.trash.empty'),
      history: (id) => call('cards.history.list', { id }),
      restoreRevision: (itemId, revisionId) => call('cards.history.restore', { itemId, revisionId }),
      clearHistory: (id) => call('cards.history.clear', { id }),
    },
    identities: {
      list: () => call('identities.list'), detail: (id) => call('identities.detail', { id }),
      add: (input) => call('identities.add', input), update: (input) => call('identities.update', input),
      delete: (id) => call('identities.delete', { id }), trash: () => call('identities.trash.list'),
      restoreTrash: (trashId) => call('identities.trash.restore', { trashId }),
      purgeTrash: (trashId) => call('identities.trash.purge', { trashId }), emptyTrash: () => call('identities.trash.empty'),
      history: (id) => call('identities.history.list', { id }),
      restoreRevision: (itemId, revisionId) => call('identities.history.restore', { itemId, revisionId }),
      clearHistory: (id) => call('identities.history.clear', { id }),
    },
    ssh: {
      list: () => call('ssh.list'), detail: (id) => call('ssh.detail', { id }),
      add: (input) => call('ssh.add', input), update: (input) => call('ssh.update', input),
      delete: (id) => call('ssh.delete', { id }), copyPassword: (id, password) => copy('ssh.copy-password', id, password),
      copyPublicKey: (id) => copy('ssh.copy-public-key', id), copyPrivateKey: (id, password) => copy('ssh.copy-private-key', id, password),
      copyKeyPassphrase: (id, password) => copy('ssh.copy-key-passphrase', id, password),
      importFromClipboard: () => call('ssh.import-clipboard'), generateKeyPair: (input) => call('ssh.generate-key-pair', input),
      trash: () => call('ssh.trash.list'), restoreTrash: (trashId) => call('ssh.trash.restore', { trashId }),
      purgeTrash: (trashId) => call('ssh.trash.purge', { trashId }), emptyTrash: () => call('ssh.trash.empty'),
      history: (id) => call('ssh.history.list', { id }),
      restoreRevision: (itemId, revisionId) => call('ssh.history.restore', { itemId, revisionId }),
      clearHistory: (id) => call('ssh.history.clear', { id }), scanLocalKeys: () => call('ssh.scan'),
      importScannedKeys: (sessionId, selections) => call('ssh.scan.commit', {
        sessionId,
        entryIds: selections.map(({ entryId }) => entryId),
        publicKeyOverrides: Object.fromEntries(
          selections.flatMap(({ entryId, publicKey }) => publicKey === null ? [] : [[entryId, publicKey]]),
        ),
      }),
      cancelKeyScan: (sessionId) => call('ssh.scan.cancel', { sessionId }),
      inspectHostKey: (accountId) => call('ssh.inspect-host-key', { accountId }),
      installPublicKey: (input) => call('ssh.install-public-key', input), externalClients: () => call('ssh.external-clients'),
      launch: (input) => call('ssh.launch', input),
    },
    secrets: {
      list: () => call('secrets.list'), detail: (id) => call('secrets.detail', { id }),
      add: (input) => call('secrets.add', input), update: (input) => call('secrets.update', input),
      delete: (id) => call('secrets.delete', { id }), copyValue: (id, password) => copy('secrets.copy-value', id, password),
    },
    services: {
      list: (query) => call('services.list', query ? { query } : {}), detail: (id) => call('services.detail', { id }),
      add: (input) => call('services.add', input), update: (input) => call('services.update', input),
      delete: (id) => call('services.delete', { id }),
      link: (serviceId, relationship) => call('services.link', { serviceId, relationship }),
      unlink: (serviceId, relationship) => call('services.unlink', { serviceId, relationship }),
      move: (fromId, toId, relationship) => call('services.move', { fromId, toId, relationship }),
      merge: (sourceId, destinationId) => call('services.merge', { sourceId, destinationId }),
      split: (sourceId, service, relationships) => call('services.split', { sourceId, service, relationships }),
      ignoreSuggestion: (input) => call('services.ignore-suggestion', input),
      trash: () => call('services.trash.list'), restoreTrash: (trashId) => call('services.trash.restore', { trashId }),
      purgeTrash: (trashId) => call('services.trash.purge', { trashId }), emptyTrash: () => call('services.trash.empty'),
      history: (id) => call('services.history.list', { id }),
      restoreRevision: (serviceId, revisionId) => call('services.history.restore', { serviceId, revisionId }),
      clearHistory: (id) => call('services.history.clear', { id }),
      previewAggregation: () => call('services.aggregation.preview'),
      applyAggregation: (planId) => call('services.aggregation.apply', { planId }),
      rollbackAggregation: (batchId) => call('services.aggregation.rollback', { batchId }),
      automaticLinkingEnabled: () => call('services.automatic-linking.get'),
      updateAutomaticLinking: (enabled) => call('services.automatic-linking.update', { enabled }),
      openSite: (serviceId, site) => call('services.open-site', { serviceId, site }),
    },
    apiEnvironments: {
      list: (serviceId) => call('api-environments.list', { serviceId }),
      detail: (id) => call('api-environments.detail', { id }),
      add: (input) => call('api-environments.add', input),
      update: (input) => call('api-environments.update', input),
      delete: (id) => call('api-environments.delete', { id }),
      trash: (serviceId) => call('api-environments.trash.list', { serviceId }),
      restoreTrash: (trashId) => call('api-environments.trash.restore', { trashId }),
      purgeTrash: (trashId) => call('api-environments.trash.purge', { trashId }),
      history: (id) => call('api-environments.history.list', { id }),
      restoreRevision: (id, revisionId) => call('api-environments.history.restore', { id, revisionId }),
      clearHistory: (id) => call('api-environments.history.clear', { id }),
    },
    apiRequests: {
      prepare: (input) => call('api-requests.prepare', input),
      execute: (executionRef) => call('api-requests.execute', { executionRef }),
      cancel: (executionRef) => call('api-requests.cancel', { executionRef }),
    },
    emailOtp: {
      accounts: () => call('email.accounts'), addAccount: (input) => call('email.accounts.add', input),
      updateAccount: (input) => call('email.accounts.update', input), deleteAccount: (id) => call('email.accounts.delete', { id }),
      testAccount: (id) => call('email.accounts.test', { id }), settings: () => call('email.settings.get'),
      updateSettings: (input) => call('email.settings.update', input), scan: () => call('email.scan'),
      copyCode: (code) => call('email.copy-code', { code }), oauthAvailability: () => call('email.oauth.availability'),
      connectOAuth: (input) => call('email.oauth.connect', input),
      onCandidates: (callback) => {
        let active = true; let unlisten: (() => void) | undefined;
        void listen<Parameters<typeof callback>[0]>('email-otp-candidates', (event) => callback(event.payload)).then((next) => {
          if (active) unlisten = next; else next();
        });
        return () => { active = false; unlisten?.(); };
      },
    },
    imports: {
      select: (source) => call('imports.select', { source }), commit: (sessionId) => call('imports.commit', { sessionId }),
      cancel: (sessionId) => call('imports.cancel', { sessionId }),
    },
    activity: () => { void invoke('desktop_activity'); },
  };
}

export async function installTauriVaultMeshApi(): Promise<void> {
  if (window.vaultMesh) throw new Error('VaultMesh API 已安装。');
  Object.defineProperty(window, 'vaultMesh', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze(createTauriVaultMeshApi()),
  });
}
