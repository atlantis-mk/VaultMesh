import { describe, expect, it } from 'vitest';

import {
  LoginItemSummarySchema,
  LoginItemUpdateSchema,
  RecoveryCodesAccessSchema,
  RecoveryCodeCopyAccessSchema,
  RecoveryCodesSchema,
  RecoveryCodeFileResultSchema,
  BiometricStatusSchema,
  PinSetupSchema,
  PinStatusSchema,
  MasterPasswordInputSchema,
  TotpCodeSchema,
  SecretAccessSchema,
  RevealedPasswordSchema,
  PasswordHealthReportSchema,
  PaymentCardInputSchema,
  PaymentCardSummarySchema,
  SshCredentialInputSchema,
  SshCredentialSummarySchema,
  SshKeyGenerationInputSchema,
  SshKeyGenerationResultSchema,
  SshKeyScanCommitSchema,
  SshKeyScanPreviewSchema,
  SshPublicKeyInstallSchema,
  SshPublicKeyInstallResultSchema,
  SecretItemInputSchema,
  SecretItemSummarySchema,
  PasskeyProxyRequestSchema,
  ImportPreviewSchema,
  SecuritySettingsSchema,
  DesktopStartupSettingsSchema,
  DesktopBrowserIntegrationStatusSchema,
  DEFAULT_DESKTOP_STARTUP_SETTINGS,
  EmailOtpCandidateSchema,
  EmailOtpCopySchema,
  DEFAULT_SECURITY_SETTINGS,
  AgentClientSummarySchema,
  AgentPermissionRequestSchema,
  AgentAccessSettingsSchema,
  AgentBrokerStatusSchema,
  ServiceAggregationPlanSchema,
  ServiceDetailSchema,
  ServiceInputSchema,
  ApiEnvironmentDetailSchema,
  ApiEnvironmentInputSchema,
  ApiRequestExecutionResultSchema,
  ApiRequestInputSchema,
  ApiRequestPreviewSchema,
} from '../../src/shared/contracts';

describe('desktop IPC contracts', () => {
  it('keeps Service contracts navigation-only and bounds automatic plans', () => {
    const id = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    expect(ServiceInputSchema.parse({ name: 'Example', description: null, tags: ['work'], sites: ['https://example.test'] }).name).toBe('Example');
    expect(() => ServiceInputSchema.parse({ name: 'Example', description: null, tags: [], sites: ['ssh://example.test'] })).toThrow();
    const unsafeDetail = {
      id, name: 'Example', description: null, tags: [], sites: ['https://example.test'],
      relationships: [{ itemKind: 'login', itemId: id, source: 'automatic-exact-host-v1', username: 'must-not-cross' }],
      counts: { login: 1, secret: 0, ssh: 0, identity: 0 }, createdAt: 1, updatedAt: 1,
      password: 'must-not-cross',
    };
    expect(() => ServiceDetailSchema.parse(unsafeDetail)).toThrow();
    const detail = ServiceDetailSchema.parse({
      id, name: 'Example', description: null, tags: [], sites: ['https://example.test'],
      relationships: [{ itemKind: 'login', itemId: id, source: 'automatic-exact-host-v1' }],
      counts: { login: 1, secret: 0, ssh: 0, identity: 0 }, createdAt: 1, updatedAt: 1,
    });
    expect(detail.relationships[0]).not.toHaveProperty('username');
    expect(ServiceAggregationPlanSchema.parse({
      planId: 'a'.repeat(64), vaultNamespace: 'b'.repeat(64), catalogRevision: 'c'.repeat(64),
      ruleVersion: 'exact-host-v1', inputDigest: 'c'.repeat(64), clusters: [],
      reviewItems: [],
      highConfidenceItemCount: 0, conflictCount: 0, ungroupedCount: 1,
    }).ungroupedCount).toBe(1);
  });

  it('keeps desktop API requests structured and results bounded', () => {
    const input = {
      environmentId: crypto.randomUUID(), method: 'POST', path: '/v1/check',
      query: [{ name: 'dry_run', value: 'true' }], headers: [{ name: 'x-trace', value: '42' }],
      body: { type: 'json', value: '{"ok":true}' },
    };
    expect(ApiRequestInputSchema.parse(input).method).toBe('POST');
    expect(() => ApiRequestInputSchema.parse({ ...input, url: 'https://evil.test' })).toThrow();
    expect(() => ApiRequestInputSchema.parse({ ...input, authorization: 'Bearer secret' })).toThrow();
    expect(ApiRequestPreviewSchema.parse({
      executionRef: crypto.randomUUID(), expiresAt: Date.now() + 60_000, method: 'POST',
      origin: 'https://api.example.test', basePath: '/v1', path: '/v1/check', bodyType: 'json',
      queryCount: 1, requestHeaderCount: 1, fixedHeaderCount: 2, authType: 'bearer',
      targetClass: 'public', mutation: true, requiresNativeConfirmation: true,
    }).mutation).toBe(true);
    expect(ApiRequestExecutionResultSchema.parse({
      state: 'execution-unknown', error: {
        code: 'transport-lost', message: '请核对远端结果。', retryable: false, executionUnknown: true,
      },
    }).state).toBe('execution-unknown');
  });
  it('keeps API environment credential bindings typed and rejects expanded secret fields', () => {
    const id = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    const input = {
      serviceId: id, name: 'Production', kind: 'production', origin: 'https://api.example.test',
      basePath: '/v1', openapiUrl: 'https://docs.example.test/openapi.json',
      auth: { type: 'bearer', credential: { itemKind: 'secret', itemId: id, field: 'secret-value', expectedSecretKind: 'access-token' } },
      fixedHeaders: [{ name: 'X-API-Version', source: { type: 'literal', value: '2026-08' } }],
    };
    expect(ApiEnvironmentInputSchema.parse(input).auth.type).toBe('bearer');
    expect(() => ApiEnvironmentInputSchema.parse({ ...input, agentEnabled: false })).toThrow();
    expect(() => ApiEnvironmentInputSchema.parse({ ...input, credentialValue: 'must-not-cross-ipc' })).toThrow();
    expect(() => ApiEnvironmentDetailSchema.parse({
      ...input, id, revision: 1, policyDigest: 'a'.repeat(64), createdAt: 1, updatedAt: 1,
      auth: { ...input.auth, credential: { ...input.auth.credential, value: 'must-not-cross-ipc' } },
    })).toThrow();
  });
  it('accepts only current Agent status fields', () => {
    const status = {
      protocolVersion: 2,
      shimPath: '/tmp/vaultmesh-agent-mcp',
      shimAvailable: true,
      confirmations: [], permissionRequests: [], authorizationRules: [], auditEvents: [], clients: [],
      access: {
        hasVault: true, runtimeUnlocked: false, clientUnlocked: false, activeLeaseCount: 0,
        settings: { unlockScope: 'connection', idleTimeoutMs: 15 * 60_000, maxUnlockDurationMs: 8 * 60 * 60_000 },
      },
      pin: { enabled: false, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 },
      tools: [{
        name: 'vaultmesh_accounts_list', version: 2, capability: 'accounts', risk: 'R0',
        requiresAccount: false, confirmation: 'none', parameters: [],
      }],
    };
    expect(AgentBrokerStatusSchema.parse(status).protocolVersion).toBe(2);
    expect(() => AgentBrokerStatusSchema.parse({ ...status, vaultFormatVersion: 3 })).toThrow();
    expect(() => AgentBrokerStatusSchema.parse({ ...status, profiles: [] })).toThrow();
    expect(() => AgentBrokerStatusSchema.parse({ ...status, permissionRules: [] })).toThrow();
  });

  it('accepts only bounded independent Agent auto-lock policies', () => {
    expect(AgentAccessSettingsSchema.parse({
      unlockScope: 'connection',
      idleTimeoutMs: 15 * 60_000,
      maxUnlockDurationMs: 8 * 60 * 60_000,
    })).toEqual({ unlockScope: 'connection', idleTimeoutMs: 900000, maxUnlockDurationMs: 28800000 });
    expect(AgentAccessSettingsSchema.parse({
      unlockScope: 'client',
      idleTimeoutMs: 15 * 60_000,
      maxUnlockDurationMs: null,
    })).toEqual({ unlockScope: 'client', idleTimeoutMs: 900000, maxUnlockDurationMs: null });
    expect(() => AgentAccessSettingsSchema.parse({
      unlockScope: 'connection',
      idleTimeoutMs: 10 * 60_000,
      maxUnlockDurationMs: 8 * 60 * 60_000,
    })).toThrow();
    expect(() => AgentAccessSettingsSchema.parse({
      unlockScope: 'connection',
      idleTimeoutMs: 15 * 60_000,
      maxUnlockDurationMs: 0,
    })).toThrow();
  });

  it('groups one paired Agent client into bounded live activities', () => {
    const firstClientId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    const secondClientId = '4b9f4db1-e209-4743-ac42-9fd365168580';
    const client = AgentClientSummarySchema.parse({
      clientId: `agent-pairing-v2-${'b'.repeat(64)}`,
      clientKey: 'cursor.team-a',
      pairingState: 'paired',
      activeSessionCount: 2,
      activities: [
        { clientId: firstClientId, processId: 100, connectedAt: 1, activeSessionCount: 1 },
        { clientId: secondClientId, processId: 101, connectedAt: 2, activeSessionCount: 1 },
      ],
    });
    expect(client.activities.map((activity) => activity.processId)).toEqual([100, 101]);
    expect(client).not.toHaveProperty('processId');
  });

  it('accepts only broker-owned dynamic permission records', () => {
    const id = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    const identity = `sha256:${'a'.repeat(64)}`;
    expect(AgentPermissionRequestSchema.parse({
      permissionRef: id, clientId: id, sessionId: id, accountRef: id,
      accountLabel: 'Example API', environment: 'test', tool: 'vaultmesh_http_request',
      operation: 'status', risk: 'R1', approvedDisplay: 'https://api.example.test', actionDisplay: 'GET /status',
      sourceItemRef: null, sourceItemKind: null, activationRequired: false,
      availableScopes: ['exact'],
      availableAllowDurations: ['once', 'connection', 'permanent'],
      availableDenyDurations: ['once', 'connection', 'permanent'],
      recommendedScope: 'exact', recommendedDuration: 'once',
      freshConfirmationRequired: false,
      createdAt: 1, expiresAt: 2,
    }).approvedDisplay).toBe('https://api.example.test');
  });

  it('rejects short master passwords', () => {
    expect(() => MasterPasswordInputSchema.parse({ masterPassword: 'short' })).toThrow();
  });

  it('does not retain an unexpected password in list results', () => {
    const result = LoginItemSummarySchema.parse({
      id: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03',
      title: 'Example',
      username: 'ada@example.test',
      password: 'must-not-cross-list-ipc',
      url: null,
      notes: null,
      hasPassword: true,
      hasTotpSecret: true,
      hasRecoveryCodes: true,
      recoveryCodes: ['must-not-cross-list-ipc'],
      autofillOnPageLoad: true,
      masterPasswordReprompt: false,
    });
    expect(result).not.toHaveProperty('password');
    expect(result).not.toHaveProperty('recoveryCodes');
    expect(result.hasPassword).toBe(true);
  });

  it('allows metadata edits without returning the existing password', () => {
    const result = LoginItemUpdateSchema.parse({
      id: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03',
      title: 'Example',
      username: 'ada@example.test',
      password: null,
      url: null,
      notes: null,
    });
    expect(result.password).toBeNull();
    expect(result.recoveryCodes).toBeNull();
    expect(result.clearRecoveryCodes).toBe(false);
  });

  it('requires a bounded master password for recovery-code reveal and copy', () => {
    const id = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    expect(RecoveryCodesAccessSchema.parse({ id, masterPassword: 'a long master password' })).toEqual({ id, masterPassword: 'a long master password' });
    expect(() => RecoveryCodesAccessSchema.parse({ id, masterPassword: null })).toThrow();
    expect(RecoveryCodeCopyAccessSchema.parse({ id, index: 99, masterPassword: 'a long master password' }).index).toBe(99);
    expect(() => RecoveryCodeCopyAccessSchema.parse({ id, index: 100, masterPassword: 'a long master password' })).toThrow();
    expect(RecoveryCodesSchema.parse({ codes: ['ABCD-EFGH'] })).toEqual({ codes: ['ABCD-EFGH'] });
    expect(() => RecoveryCodesSchema.parse({ codes: ['   '] })).toThrow();
    expect(RecoveryCodeFileResultSchema.parse({ codes: ['ABCD-EFGH'], fileName: 'codes.txt', sourceFileStatus: 'deleted', path: '/must/not/cross' })).toEqual({
      codes: ['ABCD-EFGH'], fileName: 'codes.txt', sourceFileStatus: 'deleted',
    });
  });

  it('only exposes a non-secret biometric capability state to the renderer', () => {
    expect(BiometricStatusSchema.parse({ available: true, enabled: true, kind: 'touchId' })).toEqual({
      available: true,
      enabled: true,
      kind: 'touchId',
    });
  });

  it('accepts bounded numeric PIN setup without exposing PIN in status', () => {
    expect(PinSetupSchema.parse({ pin: '123456' })).toEqual({ pin: '123456', failureLimit: 5 });
    expect(() => PinSetupSchema.parse({ pin: '1234', failureLimit: 5 })).toThrow();
    expect(() => PinSetupSchema.parse({ pin: '12ab', failureLimit: 5 })).toThrow();
    expect(() => PinSetupSchema.parse({ pin: '123456', failureLimit: 11 })).toThrow();
    const status = PinStatusSchema.parse({ enabled: true, locked: false, failureLimit: 5, failedAttempts: 1, remainingAttempts: 4, pin: '123456' });
    expect(status).not.toHaveProperty('pin');
  });

  it('only accepts a current six-digit TOTP result without a seed', () => {
    expect(TotpCodeSchema.parse({ code: '287082', period: 30, remainingSeconds: 1 })).toEqual({
      code: '287082',
      period: 30,
      remainingSeconds: 1,
    });
    expect(() => TotpCodeSchema.parse({ code: '287082', period: 30, remainingSeconds: 1, secret: 'must-not-cross-ipc' })).not.toThrow();
    const result = TotpCodeSchema.parse({ code: '287082', period: 30, remainingSeconds: 1, secret: 'must-not-cross-ipc' });
    expect(result).not.toHaveProperty('secret');
  });

  it('accepts the same bounded alphanumeric syntax for email candidates and copy requests', () => {
    const emailCandidate = {
      accountId: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03',
      accountAddress: 'ada@example.test',
      code: 'A9b2C3',
      sender: 'security@example.test',
      subject: 'Your verification code',
      receivedAt: 1_700_000_000,
    };
    expect(EmailOtpCandidateSchema.parse(emailCandidate).code).toBe('A9b2C3');
    expect(EmailOtpCopySchema.parse({ code: '48271q' })).toEqual({ code: '48271q' });
    expect(() => EmailOtpCopySchema.parse({ code: 'ABCDEF' })).toThrow();
    expect(() => EmailOtpCopySchema.parse({ code: 'A9-B2' })).toThrow();
    expect(() => EmailOtpCopySchema.parse({ code: 'A9b2C3xyz' })).toThrow();
  });

  it('accepts a per-operation master-password re-prompt without echoing it in results', () => {
    expect(SecretAccessSchema.parse({ id: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03', masterPassword: 'a long master password' })).toEqual({
      id: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03', masterPassword: 'a long master password',
    });
    const report = PasswordHealthReportSchema.parse({ weakItemIds: [], reusedItemIds: [], oldItemIds: [], score: 100, password: 'must-not-cross-ipc' });
    expect(report).not.toHaveProperty('password');
  });

  it('permits a password only in the explicit reveal result shape', () => {
    expect(RevealedPasswordSchema.parse({ password: 'a-visible-password' })).toEqual({ password: 'a-visible-password' });
    expect(() => RevealedPasswordSchema.parse({ password: '' })).toThrow();
  });

  it('accepts valid payment-card input and rejects malformed protected fields', () => {
    const input = {
      title: 'Daily card', cardholderName: 'Ada Lovelace', cardNumber: '4111 1111 1111 1111',
      expirationMonth: 12, expirationYear: 2030, securityCode: '123', pin: '1234',
      billingAddress: null, notes: null,
    };
    expect(PaymentCardInputSchema.parse(input).cardNumber).toBe(input.cardNumber);
    expect(() => PaymentCardInputSchema.parse({ ...input, securityCode: '12a' })).toThrow();
    expect(() => PaymentCardInputSchema.parse({ ...input, expirationMonth: 13 })).toThrow();
  });

  it('strips protected payment-card fields from renderer summaries', () => {
    const result = PaymentCardSummarySchema.parse({
      id: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03', title: 'Daily card',
      cardholderName: 'Ada Lovelace', maskedNumber: '•••• 1111', expirationMonth: 12,
      expirationYear: 2030, issuer: null, network: 'Visa', notes: null,
      hasSecurityCode: true, hasPin: true,
      masterPasswordReprompt: false, cardNumber: '4111111111111111', securityCode: '123', pin: '1234',
    });
    expect(result).not.toHaveProperty('cardNumber');
    expect(result).not.toHaveProperty('securityCode');
    expect(result).not.toHaveProperty('pin');
  });

  it('allows agent-backed SSH accounts and strips all SSH secrets from summaries', () => {
    expect(SshCredentialInputSchema.parse({
      title: 'Server', host: 'server.test', port: 22, username: 'root', password: null,
      publicKey: null, privateKey: null, keyPassphrase: null, notes: null, folder: null,
      favorite: false, masterPasswordReprompt: false, recordKind: 'account',
    }).password).toBeNull();
    expect(SshCredentialInputSchema.parse({
      title: 'Server', host: 'server.test', port: 22, username: 'root', password: 'secret',
      publicKey: null, privateKey: null, keyPassphrase: null, notes: null, folder: null,
      favorite: false, masterPasswordReprompt: false, recordKind: 'account',
    }).password).toBe('secret');
    expect(() => SshCredentialInputSchema.parse({
      title: 'Legacy combined record', host: 'server.test', port: 22, username: 'root', password: null,
      publicKey: 'ssh-ed25519 AAAAlegacy', privateKey: null, keyPassphrase: null, notes: null, folder: null,
      favorite: false, masterPasswordReprompt: false, recordKind: 'account',
    })).toThrow('SSH 账号不能绑定密钥');
    const summary = SshCredentialSummarySchema.parse({
      id: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03', title: 'Server', host: 'server.test', port: 22,
      username: 'root', hasPassword: true, hasPublicKey: true, hasPrivateKey: true,
      hasKeyPassphrase: true, keyAlgorithm: 'ssh-ed25519', publicKeyFingerprint: 'SHA256:test',
      managedSshAlias: 'home-server', notes: null, masterPasswordReprompt: true, password: 'secret', publicKey: 'public',
      privateKey: 'private', keyPassphrase: 'passphrase', recordKind: 'account',
    });
    expect(summary).not.toHaveProperty('password');
    expect(summary).not.toHaveProperty('publicKey');
    expect(summary).not.toHaveProperty('privateKey');
    expect(summary).not.toHaveProperty('keyPassphrase');
    expect(summary.managedSshAlias).toBe('home-server');
  });

  it('accepts only secret-free local SSH scan previews', () => {
    const preview = SshKeyScanPreviewSchema.parse({
      sessionId: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03', scannedCount: 2, skippedCount: 0,
      items: [{ entryId: '4b9f4db1-e209-4743-ac42-9fd365168580', name: 'id_ed25519', kind: 'keyPair', algorithm: 'ssh-ed25519', fingerprint: 'SHA256:test', duplicate: false, privateKey: 'must-not-cross-ipc', path: '/Users/example/.ssh/id_ed25519' }],
    });
    expect(preview.items[0]).not.toHaveProperty('privateKey');
    expect(preview.items[0]).not.toHaveProperty('path');
  });

  it('bounds manual public keys to selected SSH scan candidates', () => {
    const entryId = '4b9f4db1-e209-4743-ac42-9fd365168580';
    expect(SshKeyScanCommitSchema.parse({
      sessionId: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03',
      entryIds: [entryId],
      publicKeyOverrides: {
        [entryId]: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGU= manual@test',
      },
    }).publicKeyOverrides[entryId]).toContain('ssh-ed25519');
    expect(() => SshKeyScanCommitSchema.parse({
      sessionId: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03',
      entryIds: [entryId],
      publicKeyOverrides: {
        '88a4d4ca-44c3-4276-967f-02cc52ef5a8f': 'ssh-ed25519 AAAA unrelated@test',
      },
    })).toThrow('手动公钥只能提交给本次选择的 SSH 私钥');
  });

  it('validates SSH public-key installation confirmation and optional reauthentication', () => {
    const input = {
      accountId: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03',
      keyId: '4b9f4db1-e209-4743-ac42-9fd365168580',
      authentication: 'storedPassword' as const,
      authenticationKeyId: null,
      hostKeyFingerprint: 'SHA256:8oHDb5PRKSvrgACKsgtHc3CJKNWbEzwVSJYJh4QDaFs',
      masterPassword: 'correct horse battery staple',
    };
    expect(SshPublicKeyInstallSchema.parse(input).masterPassword).toBe(input.masterPassword);
    expect(() => SshPublicKeyInstallSchema.parse({ ...input, hostKeyFingerprint: 'MD5:unsafe' })).toThrow();
    expect(() => SshPublicKeyInstallSchema.parse({ ...input, masterPassword: 'short' })).toThrow();
    expect(SshPublicKeyInstallResultSchema.parse({
      endpoint: 'root@10.0.0.2:22',
      fingerprint: input.hostKeyFingerprint,
      status: 'alreadyPresent',
      keyLoginVerified: false,
      keyLoginVerification: 'failed',
    }).keyLoginVerification).toBe('failed');
  });

  it('validates SSH key generation algorithms, sizes and retained passphrases', () => {
    expect(SshKeyGenerationInputSchema.parse({
      label: 'Work key', algorithm: 'rsa', keySize: 3072,
      passphrase: 'private passphrase', savePassphrase: true, storage: 'managedNamed',
    }).keySize).toBe(3072);
    expect(() => SshKeyGenerationInputSchema.parse({ label: 'Bad size', algorithm: 'ed25519', keySize: 4096 })).toThrow();
    expect(() => SshKeyGenerationInputSchema.parse({ label: 'Bad size', algorithm: 'rsa', keySize: 521 })).toThrow();
    expect(() => SshKeyGenerationInputSchema.parse({ label: 'No passphrase', algorithm: 'mldsa', keySize: null, savePassphrase: true })).toThrow();
    expect(() => SshKeyGenerationInputSchema.parse({ label: 'line one\nline two', algorithm: 'ed25519', keySize: null })).toThrow();
    const result = SshKeyGenerationResultSchema.parse({
      algorithm: 'ssh-ed25519', publicKey: 'ssh-ed25519 AAAA Work',
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----',
      keyPassphrase: null, unexpectedSecret: 'stripped',
    });
    expect(result).not.toHaveProperty('unexpectedSecret');
  });

  it('classifies developer secrets while stripping their values from summaries', () => {
    const input = SecretItemInputSchema.parse({
      title: 'GitHub work token', kind: 'access-token', provider: 'GitHub', account: 'ada',
      secret: 'ghp_private_value', environment: 'Production', scopes: ['repo', 'read:org'],
      expiresAt: '2030-12-31', website: 'https://github.com/settings/tokens', notes: null,
      folder: 'Work', favorite: true, masterPasswordReprompt: true,
    });
    expect(input.kind).toBe('access-token');
    expect(() => SecretItemInputSchema.parse({ ...input, kind: 'github-token' })).toThrow();
    const summary = SecretItemSummarySchema.parse({
      id: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03', ...input, secret: 'must-not-cross-list-ipc',
    });
    expect(summary).not.toHaveProperty('secret');
    expect(summary.provider).toBe('GitHub');
  });

  it('accepts an optional opaque Login hint for Passkey creation', () => {
    const requestDetailsJson = '{"rp":{"id":"example.test"}}';
    const loginId = '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03';
    expect(PasskeyProxyRequestSchema.parse({ requestDetailsJson })).toEqual({ requestDetailsJson });
    expect(PasskeyProxyRequestSchema.parse({ requestDetailsJson, loginId }).loginId).toBe(loginId);
    expect(() => PasskeyProxyRequestSchema.parse({ requestDetailsJson, loginId: 'not-a-uuid' })).toThrow();
  });

  it('only exposes secret-free mixed-type import previews', () => {
    const preview = ImportPreviewSchema.parse({
      sessionId: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03', source: 'bitwarden', fileName: 'export.json',
      importableCount: 2, loginCount: 1, paymentCardCount: 1, sshCredentialCount: 0, skippedCount: 0,
      items: [
        { type: 'login', title: 'Example', detail: 'ada@example.test', password: 'secret' },
        { type: 'paymentCard', title: 'Daily card', detail: 'Ada Lovelace · Visa', cardNumber: '4111111111111111' },
      ],
    });
    expect(preview.items[0]).not.toHaveProperty('password');
    expect(preview.items[1]).not.toHaveProperty('cardNumber');
  });

  it('keeps configurable security timeouts within safe limits', () => {
    expect(SecuritySettingsSchema.parse(DEFAULT_SECURITY_SETTINGS)).toEqual(DEFAULT_SECURITY_SETTINGS);
    expect(() => SecuritySettingsSchema.parse({
      ...DEFAULT_SECURITY_SETTINGS,
      clipboardClearTimeoutMs: 5 * 60_000,
    })).toThrow();
    expect(() => SecuritySettingsSchema.parse({
      ...DEFAULT_SECURITY_SETTINGS,
      idleTimeoutMs: 0,
    })).toThrow();
  });

  it('keeps desktop startup settings boolean-only and default-enabled', () => {
    expect(DesktopStartupSettingsSchema.parse(DEFAULT_DESKTOP_STARTUP_SETTINGS)).toEqual({ enabled: true });
    expect(() => DesktopStartupSettingsSchema.parse({ enabled: true, arguments: ['--arbitrary'] })).toThrow();
  });

  it('keeps browser integration diagnostics non-secret and bounded', () => {
    expect(DesktopBrowserIntegrationStatusSchema.parse({
      supported: true,
      ready: false,
      brokerReady: true,
      hostRegistered: false,
      extensionId: 'bdneegbnjbheblmamalplnddbodcghbg',
      errorCode: 'registration-unavailable',
    }).errorCode).toBe('registration-unavailable');
    expect(() => DesktopBrowserIntegrationStatusSchema.parse({
      supported: true,
      ready: false,
      brokerReady: false,
      hostRegistered: false,
      extensionId: 'C:\\secret\\host.exe',
      errorCode: 'registry failed at HKCU\\Software',
    })).toThrow();
  });

});
