import type {
  CopyResult,
  RevealedPassword,
  BiometricStatus,
  PinInput,
  PinSetup,
  PinStatus,
  LoginItemInput,
  LoginItemDetail,
  LoginItemSummary,
  LoginItemUpdate,
  RecoveryCodes,
  RecoveryCodeFileResult,
  MasterPasswordInput,
  ImportPreview,
  ImportResult,
  ImportSource,
  VaultOperationResult,
  VaultStatus,
  UnlockEvent,
  TotpCode,
  ChangeMasterPasswordInput,
  DialogOperationResult,
  DesktopStartupSettings,
  DesktopBrowserIntegrationStatus,
  TrashItemSummary,
  LoginItemRevisionSummary,
  PasswordHealthReport,
  PaymentCardInput,
  PaymentCardUpdate,
  PaymentCardSummary,
  PaymentCardDetail,
  PaymentCardTrashSummary,
  PaymentCardRevisionSummary,
  SshCredentialInput,
  SshCredentialUpdate,
  SshCredentialSummary,
  SshCredentialDetail,
  SshKeyGenerationInput,
  SshKeyGenerationResult,
  SshCredentialTrashSummary,
  SshCredentialRevisionSummary,
  SshKeyScanPreview,
  SshKeyScanSelection,
  SshKeyImportResult,
  SshHostKeyPreview,
  SshPublicKeyInstallResult,
  SshExternalClient,
  SshLaunchInput,
  SshLaunchResult,
  SecretItemInput,
  SecretItemUpdate,
  SecretItemSummary,
  SecretItemDetail,
  SecuritySettings,
  IdentityInput,
  IdentityUpdate,
  IdentitySummary,
  IdentityDetail,
  IdentityTrashSummary,
  IdentityRevisionSummary,
  EmailAccountInput,
  EmailAccountUpdate,
  EmailAccountSummary,
  EmailOtpSettings,
  EmailOtpCandidate,
  EmailOAuthConnect,
  EmailOAuthAvailability,
  AgentBrokerStatus,
  AgentConfirmation,
  AgentPermissionChoice,
  AgentPermissionResolution,
  AgentAccessSettings,
  ServiceAggregationApplyResult,
  ServiceAggregationPlan,
  ServiceDetail,
  ServiceIgnoredSuggestion,
  ServiceInput,
  ServiceRelationship,
  ServiceRevisionSummary,
  ServiceSummary,
  ServiceTrashSummary,
  ServiceUpdate,
  ApiEnvironmentDetail,
  ApiEnvironmentInput,
  ApiEnvironmentRevisionSummary,
  ApiEnvironmentSummary,
  ApiEnvironmentTrashSummary,
  ApiEnvironmentUpdate,
  ApiRequestExecutionResult,
  ApiRequestInput,
  ApiRequestPreview,
  LanPairingStatus,
  LanSyncStatus,
  LanSyncConflict,
  LanTrustedPeer,
} from './contracts';
import type { SshCommandImport } from '@vaultmesh/ssh-command-parser';

export interface VaultMeshApi {
  desktop: {
    startupSettings(): Promise<DesktopStartupSettings>;
    updateStartupSettings(input: DesktopStartupSettings): Promise<DesktopStartupSettings>;
    browserIntegrationStatus(): Promise<DesktopBrowserIntegrationStatus>;
    retryBrowserIntegration(): Promise<DesktopBrowserIntegrationStatus>;
  };
  vault: {
    create(input: MasterPasswordInput): Promise<VaultOperationResult>;
    unlock(input: MasterPasswordInput): Promise<VaultOperationResult>;
    lock(): Promise<VaultStatus>;
    status(): Promise<VaultStatus>;
    unlockHistory(): Promise<UnlockEvent[]>;
    backup(): Promise<DialogOperationResult>;
    restore(input: MasterPasswordInput): Promise<VaultOperationResult>;
    changeMasterPassword(input: ChangeMasterPasswordInput): Promise<VaultStatus>;
    onChanged(callback: () => void): () => void;
    onLocked(callback: () => void): () => void;
    biometricStatus(): Promise<BiometricStatus>;
    enableBiometric(): Promise<BiometricStatus>;
    disableBiometric(): Promise<BiometricStatus>;
    unlockWithBiometrics(): Promise<VaultOperationResult>;
    pinStatus(): Promise<PinStatus>;
    enablePin(input: PinSetup): Promise<PinStatus>;
    disablePin(): Promise<PinStatus>;
    unlockWithPin(input: PinInput): Promise<VaultOperationResult>;
  };
  security: {
    settings(): Promise<SecuritySettings>;
    updateSettings(input: SecuritySettings): Promise<SecuritySettings>;
  };
  lan: {
    syncStatus(): Promise<LanSyncStatus>;
    enableSync(pairingRef: string): Promise<{ ok: true }>;
    disableSync(pairingRef: string): Promise<{ ok: true }>;
    retrySync(pairingRef: string): Promise<{ ok: true }>;
    syncConflicts(): Promise<LanSyncConflict[]>;
    restoreSyncConflict(id: string): Promise<{ ok: true }>;
    clearSyncConflicts(): Promise<{ ok: true }>;
    status(): Promise<LanPairingStatus>;
    startDiscovery(): Promise<LanPairingStatus>;
    stopDiscovery(): Promise<LanPairingStatus>;
    scan(): Promise<LanPairingStatus>;
    listTrusted(): Promise<LanTrustedPeer[]>;
    begin(pairingRef: string, pairingCode: string): Promise<{ started: true }>;
    revoke(pairingRef: string): Promise<{ revoked: true }>;
    rename(pairingRef: string, label: string): Promise<{ renamed: true }>;
  };
  agent: {
    status(): Promise<AgentBrokerStatus>;
    enablePin(input: PinSetup): Promise<PinStatus>;
    disablePin(): Promise<PinStatus>;
    lockAllAccess(): Promise<{ locked: true }>;
    lockClientAccess(clientId: string): Promise<{ locked: true }>;
    updateAccessSettings(input: AgentAccessSettings): Promise<AgentAccessSettings>;
    activateAction(permissionRef: string, choice: AgentPermissionChoice): Promise<AgentPermissionResolution>;
    approveConfirmation(confirmationRef: string): Promise<AgentConfirmation>;
    rejectConfirmation(confirmationRef: string): Promise<{ rejected: true }>;
    resolvePermission(permissionRef: string, choice: AgentPermissionChoice): Promise<AgentPermissionResolution>;
    resetAuthorizationRule(ruleId: string): Promise<{ deleted: true }>;
    clearAudit(): Promise<{ cleared: true }>;
    revokeClient(clientId: string): Promise<{ revoked: true }>;
    onPairingRequested(callback: () => void): () => void;
  };
  items: {
    list(): Promise<LoginItemSummary[]>;
    detail(id: string): Promise<LoginItemDetail>;
    add(input: LoginItemInput): Promise<LoginItemSummary>;
    update(input: LoginItemUpdate): Promise<LoginItemSummary>;
    delete(id: string): Promise<void>;
    copyUsername(id: string): Promise<CopyResult>;
    copyPassword(id: string, masterPassword?: string): Promise<CopyResult>;
    revealPassword(id: string, masterPassword?: string): Promise<RevealedPassword>;
    totpCode(id: string, masterPassword?: string): Promise<TotpCode>;
    copyTotp(id: string, masterPassword?: string): Promise<CopyResult>;
    recoveryCodes(id: string, masterPassword: string): Promise<RecoveryCodes>;
    copyRecoveryCode(id: string, index: number, masterPassword: string): Promise<CopyResult>;
    importRecoveryCodesFile(): Promise<RecoveryCodeFileResult | null>;
    autofillCandidates(url: string): Promise<LoginItemSummary[]>;
    trash(): Promise<TrashItemSummary[]>;
    restoreTrash(trashId: string): Promise<LoginItemSummary>;
    purgeTrash(trashId: string): Promise<void>;
    emptyTrash(): Promise<void>;
    history(itemId: string): Promise<LoginItemRevisionSummary[]>;
    restoreRevision(itemId: string, revisionId: string): Promise<LoginItemSummary>;
    clearHistory(itemId: string): Promise<void>;
    passwordHealth(): Promise<PasswordHealthReport>;
  };
  cards: {
    list(): Promise<PaymentCardSummary[]>;
    detail(id: string): Promise<PaymentCardDetail>;
    add(input: PaymentCardInput): Promise<PaymentCardSummary>;
    update(input: PaymentCardUpdate): Promise<PaymentCardSummary>;
    delete(id: string): Promise<void>;
    copyNumber(id: string, masterPassword?: string): Promise<CopyResult>;
    copySecurityCode(id: string, masterPassword?: string): Promise<CopyResult>;
    copyPin(id: string, masterPassword?: string): Promise<CopyResult>;
    trash(): Promise<PaymentCardTrashSummary[]>;
    restoreTrash(trashId: string): Promise<PaymentCardSummary>;
    purgeTrash(trashId: string): Promise<void>;
    emptyTrash(): Promise<void>;
    history(itemId: string): Promise<PaymentCardRevisionSummary[]>;
    restoreRevision(itemId: string, revisionId: string): Promise<PaymentCardSummary>;
    clearHistory(itemId: string): Promise<void>;
  };
  identities: {
    list(): Promise<IdentitySummary[]>;
    detail(id: string): Promise<IdentityDetail>;
    add(input: IdentityInput): Promise<IdentitySummary>;
    update(input: IdentityUpdate): Promise<IdentitySummary>;
    delete(id: string): Promise<void>;
    trash(): Promise<IdentityTrashSummary[]>;
    restoreTrash(trashId: string): Promise<IdentitySummary>;
    purgeTrash(trashId: string): Promise<void>;
    emptyTrash(): Promise<void>;
    history(itemId: string): Promise<IdentityRevisionSummary[]>;
    restoreRevision(itemId: string, revisionId: string): Promise<IdentitySummary>;
    clearHistory(itemId: string): Promise<void>;
  };
  ssh: {
    list(): Promise<SshCredentialSummary[]>;
    detail(id: string): Promise<SshCredentialDetail>;
    add(input: SshCredentialInput): Promise<SshCredentialSummary>;
    update(input: SshCredentialUpdate): Promise<SshCredentialSummary>;
    delete(id: string): Promise<void>;
    copyPassword(id: string, masterPassword?: string): Promise<CopyResult>;
    copyPublicKey(id: string): Promise<CopyResult>;
    copyPrivateKey(id: string, masterPassword?: string): Promise<CopyResult>;
    copyKeyPassphrase(id: string, masterPassword?: string): Promise<CopyResult>;
    importFromClipboard(): Promise<SshCommandImport>;
    generateKeyPair(input: SshKeyGenerationInput): Promise<SshKeyGenerationResult>;
    trash(): Promise<SshCredentialTrashSummary[]>;
    restoreTrash(trashId: string): Promise<SshCredentialSummary>;
    purgeTrash(trashId: string): Promise<void>;
    emptyTrash(): Promise<void>;
    history(itemId: string): Promise<SshCredentialRevisionSummary[]>;
    restoreRevision(itemId: string, revisionId: string): Promise<SshCredentialSummary>;
    clearHistory(itemId: string): Promise<void>;
    scanLocalKeys(): Promise<SshKeyScanPreview>;
    importScannedKeys(sessionId: string, selections: SshKeyScanSelection[]): Promise<SshKeyImportResult>;
    cancelKeyScan(sessionId: string): Promise<void>;
    inspectHostKey(accountId: string): Promise<SshHostKeyPreview>;
    installPublicKey(input: { accountId: string; keyId: string; authentication: 'storedPassword' | 'sshAgent' | 'authenticationKey'; authenticationKeyId: string | null; hostKeyFingerprint: string; masterPassword: string | null }): Promise<SshPublicKeyInstallResult>;
    externalClients(): Promise<SshExternalClient[]>;
    launch(input: SshLaunchInput): Promise<SshLaunchResult>;
  };
  secrets: {
    list(): Promise<SecretItemSummary[]>;
    detail(id: string): Promise<SecretItemDetail>;
    add(input: SecretItemInput): Promise<SecretItemSummary>;
    update(input: SecretItemUpdate): Promise<SecretItemSummary>;
    delete(id: string): Promise<void>;
    copyValue(id: string, masterPassword?: string): Promise<CopyResult>;
  };
  services: {
    list(query?: string): Promise<ServiceSummary[]>;
    detail(id: string): Promise<ServiceDetail>;
    add(input: ServiceInput): Promise<ServiceSummary>;
    update(input: ServiceUpdate): Promise<ServiceSummary>;
    delete(id: string): Promise<void>;
    link(serviceId: string, relationship: ServiceRelationship): Promise<ServiceDetail>;
    unlink(serviceId: string, relationship: ServiceRelationship): Promise<ServiceDetail>;
    move(fromId: string, toId: string, relationship: ServiceRelationship): Promise<ServiceDetail>;
    merge(sourceId: string, destinationId: string): Promise<ServiceDetail>;
    split(sourceId: string, service: ServiceInput, relationships: ServiceRelationship[]): Promise<ServiceDetail>;
    ignoreSuggestion(input: ServiceIgnoredSuggestion): Promise<void>;
    trash(): Promise<ServiceTrashSummary[]>;
    restoreTrash(trashId: string): Promise<ServiceSummary>;
    purgeTrash(trashId: string): Promise<void>;
    emptyTrash(): Promise<void>;
    history(id: string): Promise<ServiceRevisionSummary[]>;
    restoreRevision(serviceId: string, revisionId: string): Promise<ServiceSummary>;
    clearHistory(id: string): Promise<void>;
    previewAggregation(): Promise<ServiceAggregationPlan>;
    applyAggregation(planId: string): Promise<ServiceAggregationApplyResult>;
    rollbackAggregation(batchId: string): Promise<void>;
    automaticLinkingEnabled(): Promise<boolean>;
    updateAutomaticLinking(enabled: boolean): Promise<boolean>;
    openSite(serviceId: string, site: string): Promise<{ opened: true }>;
  };
  apiEnvironments: {
    list(serviceId: string): Promise<ApiEnvironmentSummary[]>;
    detail(id: string): Promise<ApiEnvironmentDetail>;
    add(input: ApiEnvironmentInput): Promise<ApiEnvironmentSummary>;
    update(input: ApiEnvironmentUpdate): Promise<ApiEnvironmentSummary>;
    delete(id: string): Promise<void>;
    trash(serviceId: string): Promise<ApiEnvironmentTrashSummary[]>;
    restoreTrash(trashId: string): Promise<ApiEnvironmentSummary>;
    purgeTrash(trashId: string): Promise<void>;
    history(id: string): Promise<ApiEnvironmentRevisionSummary[]>;
    restoreRevision(id: string, revisionId: string): Promise<ApiEnvironmentSummary>;
    clearHistory(id: string): Promise<void>;
  };
  apiRequests: {
    prepare(input: ApiRequestInput): Promise<ApiRequestPreview>;
    execute(executionRef: string): Promise<ApiRequestExecutionResult>;
    cancel(executionRef: string): Promise<{ cancelled: boolean }>;
  };
  emailOtp: {
    accounts(): Promise<EmailAccountSummary[]>;
    addAccount(input: EmailAccountInput): Promise<EmailAccountSummary>;
    updateAccount(input: EmailAccountUpdate): Promise<EmailAccountSummary>;
    deleteAccount(id: string): Promise<void>;
    testAccount(id: string): Promise<EmailAccountSummary>;
    settings(): Promise<EmailOtpSettings>;
    updateSettings(input: EmailOtpSettings): Promise<EmailOtpSettings>;
    scan(): Promise<EmailOtpCandidate[]>;
    copyCode(code: string): Promise<CopyResult>;
    oauthAvailability(): Promise<EmailOAuthAvailability>;
    connectOAuth(input: EmailOAuthConnect): Promise<EmailAccountSummary>;
    onCandidates(callback: (candidates: EmailOtpCandidate[]) => void): () => void;
  };
  imports: {
    select(source: ImportSource): Promise<ImportPreview | null>;
    commit(sessionId: string): Promise<ImportResult>;
    cancel(sessionId: string): Promise<void>;
  };
  activity(): void;
}
