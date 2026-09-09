import { z } from 'zod';

const optionalText = z.string().trim().max(10_000).nullable();
const optionalShortText = z.string().trim().max(256).nullable().default(null);
const additionalUrls = z.array(z.string().trim().min(1).max(10_000)).max(20).default([]);

export const LoginCustomFieldSchema = z.object({
  label: z.string().trim().min(1).max(256),
  value: z.string().max(10_000),
});

export const RecoveryCodeSchema = z.string().min(1).max(256).refine(
  (value) => value.trim().length > 0,
  '恢复码不能为空',
);

export const MasterPasswordInputSchema = z.object({
  masterPassword: z.string().min(8).max(1_024),
});

export const PinInputSchema = z.object({
  pin: z.string().regex(/^\d{6}$/, 'PIN 必须为 6 位数字'),
});

export const PinSetupSchema = PinInputSchema.extend({
  failureLimit: z.number().int().min(3).max(10).default(5),
});

export const ChangeMasterPasswordSchema = z.object({
  currentPassword: z.string().min(8).max(1_024),
  newPassword: z.string().min(8).max(1_024),
});

export const SecretAccessSchema = z.object({
  id: z.uuid(),
  masterPassword: z.string().min(8).max(1_024).nullable().default(null),
});

export const RecoveryCodesAccessSchema = z.object({
  id: z.uuid(),
  masterPassword: z.string().min(8).max(1_024),
});

export const RecoveryCodeCopyAccessSchema = RecoveryCodesAccessSchema.extend({
  index: z.number().int().min(0).max(99),
});

export const RecoveryCodesSchema = z.object({
  codes: z.array(RecoveryCodeSchema).min(1).max(100),
});

export const RecoveryCodeFileResultSchema = RecoveryCodesSchema.extend({
  fileName: z.string().min(1).max(1_024),
  sourceFileStatus: z.enum(['deleted', 'kept', 'failed']),
});

/** Passwords cross IPC only after an explicit reveal action. */
export const RevealedPasswordSchema = z.object({
  password: z.string().min(1).max(10_000),
});

export const LoginItemInputSchema = z.object({
  title: z.string().trim().min(1).max(256),
  username: z.string().max(2_048),
  password: z.string().min(1).max(10_000),
  url: optionalText,
  notes: optionalText,
  folder: optionalShortText,
  favorite: z.boolean().default(false),
  totpSecret: z.string().min(1).max(10_000).nullable().default(null),
  recoveryCodes: z.array(RecoveryCodeSchema).max(100).default([]),
  additionalUrls,
  autofillOnPageLoad: z.boolean().default(true),
  masterPasswordReprompt: z.boolean().default(false),
  customFields: z.array(LoginCustomFieldSchema).max(50).default([]),
});

export const LoginItemUpdateSchema = z.object({
  id: z.uuid(),
  title: z.string().trim().min(1).max(256),
  username: z.string().max(2_048),
  password: z.string().max(10_000).nullable(),
  url: optionalText,
  notes: optionalText,
  folder: optionalShortText,
  favorite: z.boolean().default(false),
  totpSecret: z.string().min(1).max(10_000).nullable().default(null),
  clearTotpSecret: z.boolean().default(false),
  recoveryCodes: z.array(RecoveryCodeSchema).max(100).nullable().default(null),
  clearRecoveryCodes: z.boolean().default(false),
  additionalUrls,
  autofillOnPageLoad: z.boolean().default(true),
  masterPasswordReprompt: z.boolean().default(false),
  customFields: z.array(LoginCustomFieldSchema).max(50).default([]),
});

export const ItemIdSchema = z.object({ id: z.uuid() });

export const LoginItemSummarySchema = z.object({
  id: z.uuid(),
  title: z.string(),
  username: z.string(),
  url: z.string().nullable(),
  notes: z.string().nullable(),
  hasPassword: z.boolean(),
  hasTotpSecret: z.boolean(),
  hasRecoveryCodes: z.boolean(),
  autofillOnPageLoad: z.boolean(),
  masterPasswordReprompt: z.boolean(),
});

export const LoginItemDetailSchema = z.object({
  id: z.uuid(),
  title: z.string(),
  username: z.string(),
  url: z.string().nullable(),
  notes: z.string().nullable(),
  folder: z.string().nullable(),
  favorite: z.boolean(),
  hasTotpSecret: z.boolean(),
  hasRecoveryCodes: z.boolean(),
  additionalUrls: z.array(z.string()),
  autofillOnPageLoad: z.boolean(),
  masterPasswordReprompt: z.boolean(),
  customFields: z.array(LoginCustomFieldSchema),
});

export const IdentityValueSchema = z.object({ id: z.uuid().default(() => crypto.randomUUID()), label: z.string().trim().max(256), value: z.string().trim().min(1).max(2048), preferred: z.boolean().default(false) });
export const PostalAddressSchema = z.object({ id: z.uuid().default(() => crypto.randomUUID()), label: z.string().trim().max(256), addressLine1: z.string().trim().min(1).max(512), addressLine2: optionalText, city: optionalShortText, region: optionalShortText, postalCode: optionalShortText, countryCode: z.string().regex(/^[A-Za-z]{2}$/).nullable().default(null), country: optionalShortText, preferred: z.boolean().default(false) });
export const IdentityInputSchema = z.object({ title: z.string().trim().min(1).max(256), firstName: optionalShortText, middleName: optionalShortText, lastName: optionalShortText, birthDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable().default(null), emails: z.array(IdentityValueSchema).max(20).default([]), phones: z.array(IdentityValueSchema).max(20).default([]), addresses: z.array(PostalAddressSchema).max(20).default([]), organization: optionalShortText, department: optionalShortText, jobTitle: optionalShortText, website: z.url().max(2048).nullable().default(null), notes: optionalText, folder: optionalShortText, favorite: z.boolean().default(false) });
export const IdentitySummarySchema = z.object({ id: z.uuid(), title: z.string(), displayName: z.string().nullable(), organization: z.string().nullable(), folder: z.string().nullable(), favorite: z.boolean() });
export const IdentityDetailSchema = IdentityInputSchema.extend({ id: z.uuid() });
export const IdentityUpdateSchema = IdentityInputSchema.extend({ id: z.uuid() });
export const IdentityTrashSummarySchema = z.object({ trashId: z.uuid(), itemId: z.uuid(), title: z.string(), displayName: z.string().nullable(), deletedAt: z.number().int().nonnegative() });
export const IdentityRevisionSummarySchema = z.object({ revisionId: z.uuid(), itemId: z.uuid(), title: z.string(), displayName: z.string().nullable(), savedAt: z.number().int().nonnegative() });

const browserFillOrigin = z.string().url().refine((value) => {
  const parsed = new URL(value);
  return parsed.origin === value && (parsed.protocol === 'http:' || parsed.protocol === 'https:');
}, 'Expected an HTTP(S) origin');

export const BrowserAutofillCandidatesInputSchema = z.object({
  topOrigin: browserFillOrigin,
  pageUrl: z.string().url().max(10_000).refine((value) => {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  }, 'Expected an HTTP(S) page URL').optional(),
  fieldKind: z.enum(['login', 'card', 'identity', 'secret', 'ssh']).default('login'),
  pageContext: z.enum(['login', 'signup', 'password-change', 'password-reset', 'otp', 'checkout', 'profile', 'developer-secret', 'ssh-console', 'unknown']).default('unknown'),
}).strict().refine((value) => value.pageUrl == null || new URL(value.pageUrl).origin === value.topOrigin, 'Page URL must match the top origin');
export const BrowserLoginPasswordChangedInputSchema = z.object({
  id: z.uuid(),
  password: z.string().min(1).max(10_000),
}).strict();
export const BrowserCardCaptureStatusInputSchema = z.object({
  cardId: z.uuid().optional(),
  cardholderName: z.string().trim().min(1).max(256),
  cardNumber: z.string().regex(/^\d{12,19}$/),
  expirationMonth: z.number().int().min(1).max(12),
  expirationYear: z.number().int().min(1_000).max(9_999),
  securityCode: z.string().regex(/^\d{3,4}$/).nullable(),
  billingAddress: z.string().trim().max(10_000).nullable(),
}).strict();
export const BrowserAutofillCandidateSchema = z.object({
  id: z.uuid(),
  kind: z.enum(['login', 'card', 'identity', 'secret', 'ssh']),
  title: z.string().max(256),
  subtitle: z.string().max(2_048),
  matchScope: z.enum(['path', 'origin', 'domain']).optional(),
  autofillOnPageLoad: z.boolean().optional(),
  masterPasswordReprompt: z.boolean().optional(),
});

const cardExpirationMonth = z.number().int().min(1).max(12);
const cardExpirationYear = z.number().int().min(1000).max(9999);
const cardNumber = z.string().trim().min(12).max(32);
const securityCode = z.string().regex(/^\d{3,4}$/).nullable().default(null);
const cardPin = z.string().regex(/^\d{4,12}$/).nullable().default(null);

export const PaymentCardInputSchema = z.object({
  title: z.string().trim().min(1).max(256),
  cardholderName: z.string().trim().min(1).max(256),
  cardNumber,
  expirationMonth: cardExpirationMonth,
  expirationYear: cardExpirationYear,
  securityCode,
  pin: cardPin,
  issuer: optionalShortText,
  network: optionalShortText,
  billingAddress: optionalText,
  notes: optionalText,
  folder: optionalShortText,
  favorite: z.boolean().default(false),
  masterPasswordReprompt: z.boolean().default(false),
});

export const PaymentCardUpdateSchema = z.object({
  id: z.uuid(),
  title: z.string().trim().min(1).max(256),
  cardholderName: z.string().trim().min(1).max(256),
  cardNumber: cardNumber.nullable(),
  expirationMonth: cardExpirationMonth,
  expirationYear: cardExpirationYear,
  securityCode,
  clearSecurityCode: z.boolean().default(false),
  pin: cardPin,
  clearPin: z.boolean().default(false),
  issuer: optionalShortText,
  network: optionalShortText,
  billingAddress: optionalText,
  notes: optionalText,
  folder: optionalShortText,
  favorite: z.boolean().default(false),
  masterPasswordReprompt: z.boolean().default(false),
});

export const PaymentCardSummarySchema = z.object({
  id: z.uuid(),
  title: z.string(),
  cardholderName: z.string(),
  maskedNumber: z.string(),
  expirationMonth: cardExpirationMonth,
  expirationYear: cardExpirationYear,
  hasSecurityCode: z.boolean(),
  hasPin: z.boolean(),
  issuer: z.string().nullable(),
  network: z.string().nullable(),
  notes: z.string().nullable(),
  masterPasswordReprompt: z.boolean(),
});

export const PaymentCardDetailSchema = z.object({
  id: z.uuid(),
  title: z.string(),
  cardholderName: z.string(),
  maskedNumber: z.string(),
  expirationMonth: cardExpirationMonth,
  expirationYear: cardExpirationYear,
  hasSecurityCode: z.boolean(),
  hasPin: z.boolean(),
  issuer: z.string().nullable(),
  network: z.string().nullable(),
  billingAddress: z.string().nullable(),
  notes: z.string().nullable(),
  folder: z.string().nullable(),
  favorite: z.boolean(),
  masterPasswordReprompt: z.boolean(),
});

export const PaymentCardTrashSummarySchema = z.object({
  trashId: z.uuid(), itemId: z.uuid(), title: z.string(), maskedNumber: z.string(),
  deletedAt: z.number().int().nonnegative(),
});

export const PaymentCardRevisionSummarySchema = z.object({
  revisionId: z.uuid(), itemId: z.uuid(), title: z.string(), maskedNumber: z.string(),
  savedAt: z.number().int().nonnegative(),
});

const sshKeyText = z.string().min(1).max(1024 * 1024).nullable().default(null);

export const SshKeyAlgorithmSchema = z.enum(['ed25519', 'ecdsa', 'rsa', 'mldsa']);
export const SshRecordKindSchema = z.enum(['account', 'key']);

export const SshKeyGenerationInputSchema = z.object({
  label: z.string().trim().min(1).max(256).refine((value) => !/[\r\n]/.test(value), '标签不能包含换行符。'),
  algorithm: SshKeyAlgorithmSchema,
  keySize: z.union([z.literal(256), z.literal(384), z.literal(521), z.literal(2048), z.literal(3072), z.literal(4096)]).nullable().default(null),
  passphrase: z.string().min(1).max(10_000).nullable().default(null),
  savePassphrase: z.boolean().default(false),
  storage: z.enum(['managedDefault', 'managedNamed', 'vaultOnly']).default('managedDefault'),
}).superRefine((value, context) => {
  const validSize = value.algorithm === 'ecdsa'
    ? [256, 384, 521].includes(value.keySize ?? -1)
    : value.algorithm === 'rsa'
      ? [2048, 3072, 4096].includes(value.keySize ?? -1)
      : value.keySize === null;
  if (!validSize) context.addIssue({ code: 'custom', path: ['keySize'], message: '密钥长度与所选算法不匹配。' });
  if (value.savePassphrase && value.passphrase === null) {
    context.addIssue({ code: 'custom', path: ['savePassphrase'], message: '没有口令可供保存。' });
  }
  if (value.storage === 'managedDefault' && value.algorithm !== 'ed25519') {
    context.addIssue({ code: 'custom', path: ['storage'], message: '本设备默认密钥必须使用 ED25519；其他算法请使用独立受管密钥。' });
  }
});

export const SshKeyGenerationResultSchema = z.object({
  algorithm: z.string().min(1).max(128),
  publicKey: z.string().min(1).max(1024 * 1024),
  privateKey: z.string().min(1).max(1024 * 1024),
  keyPassphrase: z.string().min(1).max(10_000).nullable(),
  privateKeyPath: z.string().min(1).max(4_096).nullable().default(null),
});

export const SshCredentialInputSchema = z.object({
  title: z.string().trim().min(1).max(256),
  host: optionalShortText,
  port: z.number().int().min(1).max(65_535).default(22),
  username: z.string().max(2_048),
  password: z.string().min(1).max(10_000).nullable().default(null),
  publicKey: sshKeyText,
  privateKey: sshKeyText,
  keyPassphrase: z.string().min(1).max(10_000).nullable().default(null),
  notes: optionalText,
  folder: optionalShortText,
  favorite: z.boolean().default(false),
  masterPasswordReprompt: z.boolean().default(false),
  recordKind: SshRecordKindSchema,
}).superRefine((value, context) => {
  if (value.keyPassphrase !== null && value.privateKey === null) {
    context.addIssue({ code: 'custom', path: ['keyPassphrase'], message: '只有私钥可以设置口令。' });
  }
  if (value.recordKind === 'account' && (!value.host || !value.username.trim())) {
    context.addIssue({ code: 'custom', path: ['host'], message: 'SSH 账号必须填写主机和用户名。' });
  }
  if (value.recordKind === 'account' && (value.publicKey !== null || value.privateKey !== null || value.keyPassphrase !== null)) {
    context.addIssue({ code: 'custom', path: ['publicKey'], message: 'SSH 账号不能绑定密钥，请单独创建 SSH 密钥记录。' });
  }
  if (value.recordKind === 'key' && value.publicKey === null && value.privateKey === null) {
    context.addIssue({ code: 'custom', path: ['publicKey'], message: 'SSH 密钥必须包含公钥或私钥。' });
  }
});

export const SshCredentialUpdateSchema = z.object({
  id: z.uuid(),
  title: z.string().trim().min(1).max(256),
  host: optionalShortText,
  port: z.number().int().min(1).max(65_535),
  username: z.string().max(2_048),
  password: z.string().min(1).max(10_000).nullable(),
  clearPassword: z.boolean().default(false),
  publicKey: sshKeyText,
  clearPublicKey: z.boolean().default(false),
  privateKey: sshKeyText,
  clearPrivateKey: z.boolean().default(false),
  keyPassphrase: z.string().min(1).max(10_000).nullable(),
  clearKeyPassphrase: z.boolean().default(false),
  notes: optionalText,
  folder: optionalShortText,
  favorite: z.boolean().default(false),
  masterPasswordReprompt: z.boolean().default(false),
  recordKind: SshRecordKindSchema,
}).superRefine((value, context) => {
  if (value.recordKind === 'account' && (!value.host || !value.username.trim())) {
    context.addIssue({ code: 'custom', path: ['host'], message: 'SSH 账号必须填写主机和用户名。' });
  }
  if (value.recordKind === 'account' && (value.publicKey !== null || value.privateKey !== null || value.keyPassphrase !== null)) {
    context.addIssue({ code: 'custom', path: ['publicKey'], message: 'SSH 账号不能绑定密钥，请单独创建 SSH 密钥记录。' });
  }
});

export const SshCredentialSummarySchema = z.object({
  id: z.uuid(), title: z.string(), host: z.string().nullable(), port: z.number().int(),
  username: z.string(), hasPassword: z.boolean(), hasPublicKey: z.boolean(),
  hasPrivateKey: z.boolean(), hasKeyPassphrase: z.boolean(), keyAlgorithm: z.string().nullable(),
  publicKeyFingerprint: z.string().nullable(),
  managedSshAlias: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/).nullable().default(null),
  notes: z.string().nullable(),
  masterPasswordReprompt: z.boolean(),
  recordKind: SshRecordKindSchema,
});

export const SshCredentialDetailSchema = SshCredentialSummarySchema.extend({
  folder: z.string().nullable(), favorite: z.boolean(),
});

export const SshHostKeyPreviewSchema = z.object({
  accountId: z.uuid(),
  endpoint: z.string().min(1).max(2_560),
  fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]+$/),
});

export const SshPublicKeyInstallSchema = z.object({
  accountId: z.uuid(),
  keyId: z.uuid(),
  authentication: z.enum(['storedPassword', 'sshAgent', 'authenticationKey']),
  authenticationKeyId: z.uuid().nullable().default(null),
  hostKeyFingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]+$/),
  masterPassword: z.string().min(8).max(1_024).nullable().default(null),
}).strict();

export const SshPublicKeyInstallResultSchema = z.object({
  endpoint: z.string().min(1).max(2_560),
  fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]+$/),
  status: z.enum(['installed', 'alreadyPresent']),
  keyLoginVerified: z.boolean().default(false),
  keyLoginVerification: z.enum(['verified', 'unavailable', 'failed']),
});

export const SshExternalClientIdSchema = z.enum(['systemTerminal', 'vscode', 'copyCommand']);
export const SshExternalClientSchema = z.object({
  id: SshExternalClientIdSchema,
  label: z.string().min(1).max(128),
  available: z.boolean(),
});
export const SshLaunchInputSchema = z.object({
  accountId: z.uuid(),
  clientId: SshExternalClientIdSchema,
  copyPassword: z.boolean().default(false),
}).strict();
export const SshLaunchResultSchema = z.object({
  launched: z.boolean(),
  command: z.string().min(1).max(16_384),
  passwordCopied: z.boolean(),
  passwordCopySkipped: z.boolean(),
  authentication: z.enum(['key', 'password', 'sshAgent']),
});

export const SshCredentialTrashSummarySchema = z.object({
  trashId: z.uuid(), itemId: z.uuid(), title: z.string(), host: z.string().nullable(),
  deletedAt: z.number().int().nonnegative(),
});

export const SshCredentialRevisionSummarySchema = z.object({
  revisionId: z.uuid(), itemId: z.uuid(), title: z.string(), host: z.string().nullable(),
  savedAt: z.number().int().nonnegative(),
});

export const SecretItemKindSchema = z.enum([
  'api-key',
  'access-token',
  'authenticator-key',
  'client-secret',
  'webhook-secret',
  'database-credential',
  'recovery-codes',
  'certificate',
  'software-license',
  'identity-document',
  'secure-note',
  'crypto-wallet',
  'other',
]);

const secretItemMetadata = {
  title: z.string().trim().min(1).max(256),
  kind: SecretItemKindSchema,
  provider: optionalShortText,
  account: optionalShortText,
  environment: optionalShortText,
  scopes: z.array(z.string().trim().min(1).max(256)).max(50).default([]),
  expiresAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable().default(null),
  website: z.url().max(2_048).nullable().default(null),
  notes: optionalText,
  folder: optionalShortText,
  favorite: z.boolean().default(false),
  masterPasswordReprompt: z.boolean().default(false),
};

export const SecretItemInputSchema = z.object({
  ...secretItemMetadata,
  secret: z.string().min(1).max(10_000),
});

export const SecretItemUpdateSchema = z.object({
  id: z.uuid(),
  ...secretItemMetadata,
  secret: z.string().min(1).max(10_000).nullable(),
});

export const SecretItemSummarySchema = z.object({
  id: z.uuid(),
  title: z.string(),
  kind: SecretItemKindSchema,
  provider: z.string().nullable(),
  account: z.string().nullable(),
  environment: z.string().nullable(),
  expiresAt: z.string().nullable(),
  website: z.string().nullable(),
  notes: z.string().nullable(),
  favorite: z.boolean(),
  masterPasswordReprompt: z.boolean(),
  // Passkeys are protected internally as secret records but are presented as
  // login credentials. These renderer-safe fields contain no key material.
  isPasskey: z.boolean().default(false),
  loginId: z.uuid().nullable().default(null),
});

export const SecretItemDetailSchema = SecretItemSummarySchema.extend({
  scopes: z.array(z.string()),
  folder: z.string().nullable(),
});

/** Chromium serializes WebAuthn options before handing them to the extension.
 * Keep the opaque JSON bounded here; the desktop Passkey service performs the
 * full structural and relying-party validation before touching the vault. */
export const PasskeyProxyRequestSchema = z.object({
  requestDetailsJson: z.string().min(2).max(128 * 1024),
  loginId: z.uuid().optional(),
}).strict();

export const SshKeyScanCommitSchema = z.object({
  sessionId: z.uuid(),
  entryIds: z.array(z.uuid()).min(1).max(200),
  publicKeyOverrides: z.record(
    z.uuid(),
    z.string().trim().min(1).max(1024 * 1024),
  ).default({}),
}).superRefine((value, context) => {
  const selected = new Set(value.entryIds);
  const overrideIds = Object.keys(value.publicKeyOverrides);
  if (overrideIds.length > 200 || overrideIds.some((entryId) => !selected.has(entryId))) {
    context.addIssue({
      code: 'custom',
      path: ['publicKeyOverrides'],
      message: '手动公钥只能提交给本次选择的 SSH 私钥。',
    });
  }
});

export const SshKeyScanSelectionSchema = z.object({
  entryId: z.uuid(),
  publicKey: z.string().trim().min(1).max(1024 * 1024).nullable(),
});

export const SshKeyScanPreviewSchema = z.object({
  sessionId: z.uuid(), scannedCount: z.number().int().nonnegative(), skippedCount: z.number().int().nonnegative(),
  items: z.array(z.object({
    entryId: z.uuid(), name: z.string(), kind: z.enum(['keyPair', 'publicKey', 'privateKey']),
    algorithm: z.string().nullable(), fingerprint: z.string().nullable(), duplicate: z.boolean(),
  })).max(200),
});

export const SshKeyImportResultSchema = z.object({
  importedCount: z.number().int().nonnegative(), skippedCount: z.number().int().nonnegative(),
});

export const VaultStatusSchema = z.object({
  unlocked: z.boolean(),
  hasVault: z.boolean(),
  itemCount: z.number().int().nonnegative(),
});

export const UnlockEventSchema = z.object({
  eventId: z.uuid(),
  occurredAt: z.number().int().nonnegative(),
  source: z.enum(['desktop', 'desktop-pin', 'extension-master-password', 'extension-biometric', 'extension-pin']),
});

export const FillEventSchema = z.object({
  eventId: z.uuid(),
  occurredAt: z.number().int().nonnegative(),
  itemKind: z.enum(['login', 'card', 'identity', 'secret', 'ssh']),
  itemId: z.uuid(),
  itemTitle: z.string(),
  origin: z.string(),
  fieldCount: z.number().int().positive(),
});

export const FillEventInputSchema = z.object({
  itemKind: z.enum(['login', 'card', 'identity', 'secret', 'ssh']),
  itemId: z.uuid(),
  itemTitle: z.string().trim().min(1).max(300),
  origin: z.url().max(2_048).refine((value) => ['http:', 'https:'].includes(new URL(value).protocol), '仅支持 HTTP(S) 来源'),
  fieldCount: z.number().int().positive().max(200),
});

export const VaultOperationResultSchema = z.object({
  cancelled: z.boolean(),
  status: VaultStatusSchema,
});

export const DialogOperationResultSchema = z.object({ cancelled: z.boolean() });

export const DesktopStartupSettingsSchema = z.object({ enabled: z.boolean() }).strict();

export const DEFAULT_DESKTOP_STARTUP_SETTINGS: z.infer<typeof DesktopStartupSettingsSchema> = {
  enabled: true,
};

export const DesktopBrowserIntegrationStatusSchema = z.object({
  supported: z.boolean(),
  ready: z.boolean(),
  brokerReady: z.boolean(),
  hostRegistered: z.boolean(),
  extensionId: z.string().regex(/^$|^[a-p]{32}$/),
  errorCode: z.enum([
    'pairing-unavailable',
    'broker-unavailable',
    'listener-unavailable',
    'listener-stopped',
    'host-missing',
    'registration-unavailable',
    'identity-invalid',
  ]).nullable(),
}).strict();

export const TrashItemSummarySchema = z.object({
  trashId: z.uuid(), itemId: z.uuid(), title: z.string(), username: z.string(),
  deletedAt: z.number().int().nonnegative(),
});

export const LoginItemRevisionSummarySchema = z.object({
  revisionId: z.uuid(), itemId: z.uuid(), title: z.string(), username: z.string(),
  savedAt: z.number().int().nonnegative(),
});

export const RevisionIdSchema = z.object({ itemId: z.uuid(), revisionId: z.uuid() });
export const TrashIdSchema = z.object({ trashId: z.uuid() });
export const AutofillQuerySchema = z.object({ url: z.url().max(10_000) });

export const PasswordHealthReportSchema = z.object({
  weakItemIds: z.array(z.uuid()), reusedItemIds: z.array(z.uuid()), oldItemIds: z.array(z.uuid()),
  score: z.number().int().min(0).max(100),
});

export const BiometricStatusSchema = z.object({
  available: z.boolean(),
  enabled: z.boolean(),
  kind: z.literal('touchId').nullable(),
});

export const PinStatusSchema = z.object({
  enabled: z.boolean(),
  locked: z.boolean(),
  failureLimit: z.number().int().min(3).max(10),
  failedAttempts: z.number().int().min(0).max(10),
  remainingAttempts: z.number().int().min(0).max(10),
});

/**
 * Security-sensitive preferences are deliberately bounded: users can tune the
 * experience, but cannot turn a temporary unlock or copied secret into a
 * long-lived one by mistake.
 */
export const SecuritySettingsSchema = z.object({
  lockOnBlur: z.boolean(),
  idleTimeoutMs: z.number().int().min(60_000).max(30 * 60_000),
  lockOnSleep: z.boolean(),
  clipboardClearTimeoutMs: z.number().int().min(10_000).max(2 * 60_000),
  copySshPasswordOnLaunch: z.boolean().default(true),
}).strict();

export const DEFAULT_SECURITY_SETTINGS: z.infer<typeof SecuritySettingsSchema> = {
  lockOnBlur: true,
  idleTimeoutMs: 5 * 60_000,
  lockOnSleep: true,
  clipboardClearTimeoutMs: 30_000,
  copySshPasswordOnLaunch: true,
};

export const LanNearbyDeviceSchema = z.object({
  pairingRef: z.string().regex(/^lan-peer-[a-f0-9]{32}$/),
  status: z.enum([
    'unverified',
    'connecting',
    'code-rejected',
    'transport-failed',
    'secure-channel-failed',
    'certificate-exchange-failed',
    'tls-failed',
    'protocol-failed',
    'discovery-changed',
    'identity-changed',
    'peer-identity-rejected',
    'local-trust-state-failed',
    'code-attempts-exhausted',
    'persistence-sync-failed',
    'local-storage-failed',
    'peer-storage-failed',
    'connected',
  ]),
}).strict();
export const LanTrustedPeerSchema = z.object({
  pairingRef: z.string().regex(/^lan-peer-[a-f0-9]{32}$/),
  label: z.string().min(1).max(64),
  protocolMajor: z.literal(1),
}).strict();
export const LanPairingStatusSchema = z.object({
  discoverable: z.boolean(),
  expiresAt: z.number().int().nonnegative().nullable(),
  pairingCode: z.string().regex(/^\d{6}$/).nullable(),
  nearby: z.array(LanNearbyDeviceSchema).max(32),
  trusted: z.array(LanTrustedPeerSchema).max(32),
}).strict();

export type MasterPasswordInput = z.infer<typeof MasterPasswordInputSchema>;
export type PinInput = z.infer<typeof PinInputSchema>;
export type PinSetup = z.infer<typeof PinSetupSchema>;
export type ChangeMasterPasswordInput = z.infer<typeof ChangeMasterPasswordSchema>;
export type LoginItemInput = z.infer<typeof LoginItemInputSchema>;
export type LoginItemUpdate = z.infer<typeof LoginItemUpdateSchema>;
export type LoginItemSummary = z.infer<typeof LoginItemSummarySchema>;
export type LoginItemDetail = z.infer<typeof LoginItemDetailSchema>;
export type RecoveryCodes = z.infer<typeof RecoveryCodesSchema>;
export type RecoveryCodeFileResult = z.infer<typeof RecoveryCodeFileResultSchema>;
export type IdentityInput = z.infer<typeof IdentityInputSchema>;
export type IdentityUpdate = z.infer<typeof IdentityUpdateSchema>;
export type IdentitySummary = z.infer<typeof IdentitySummarySchema>;
export type IdentityDetail = z.infer<typeof IdentityDetailSchema>;
export type IdentityTrashSummary = z.infer<typeof IdentityTrashSummarySchema>;
export type IdentityRevisionSummary = z.infer<typeof IdentityRevisionSummarySchema>;
export type LoginCustomField = z.infer<typeof LoginCustomFieldSchema>;
export type PaymentCardInput = z.infer<typeof PaymentCardInputSchema>;
export type PaymentCardUpdate = z.infer<typeof PaymentCardUpdateSchema>;
export type PaymentCardSummary = z.infer<typeof PaymentCardSummarySchema>;
export type PaymentCardDetail = z.infer<typeof PaymentCardDetailSchema>;
export type PaymentCardTrashSummary = z.infer<typeof PaymentCardTrashSummarySchema>;
export type PaymentCardRevisionSummary = z.infer<typeof PaymentCardRevisionSummarySchema>;
export type SshCredentialInput = z.infer<typeof SshCredentialInputSchema>;
export type SshCredentialUpdate = z.infer<typeof SshCredentialUpdateSchema>;
export type SshCredentialSummary = z.infer<typeof SshCredentialSummarySchema>;
export type SshCredentialDetail = z.infer<typeof SshCredentialDetailSchema>;
export type SshKeyAlgorithm = z.infer<typeof SshKeyAlgorithmSchema>;
export type SshKeyGenerationInput = z.infer<typeof SshKeyGenerationInputSchema>;
export type SshKeyGenerationResult = z.infer<typeof SshKeyGenerationResultSchema>;
export type SshHostKeyPreview = z.infer<typeof SshHostKeyPreviewSchema>;
export type SshPublicKeyInstallResult = z.infer<typeof SshPublicKeyInstallResultSchema>;
export type SshExternalClientId = z.infer<typeof SshExternalClientIdSchema>;
export type SshExternalClient = z.infer<typeof SshExternalClientSchema>;
export type SshLaunchInput = z.infer<typeof SshLaunchInputSchema>;
export type SshLaunchResult = z.infer<typeof SshLaunchResultSchema>;
export type SshCredentialTrashSummary = z.infer<typeof SshCredentialTrashSummarySchema>;
export type SshCredentialRevisionSummary = z.infer<typeof SshCredentialRevisionSummarySchema>;
export type SecretItemKind = z.infer<typeof SecretItemKindSchema>;
export type SecretItemInput = z.infer<typeof SecretItemInputSchema>;
export type SecretItemUpdate = z.infer<typeof SecretItemUpdateSchema>;
export type SecretItemSummary = z.infer<typeof SecretItemSummarySchema>;
export type SecretItemDetail = z.infer<typeof SecretItemDetailSchema>;
export type SshKeyScanPreview = z.infer<typeof SshKeyScanPreviewSchema>;
export type SshKeyScanSelection = z.infer<typeof SshKeyScanSelectionSchema>;
export type SshKeyImportResult = z.infer<typeof SshKeyImportResultSchema>;
export type VaultStatus = z.infer<typeof VaultStatusSchema>;
export type UnlockEvent = z.infer<typeof UnlockEventSchema>;
export type FillEvent = z.infer<typeof FillEventSchema>;
export type FillEventInput = z.infer<typeof FillEventInputSchema>;
export type VaultOperationResult = z.infer<typeof VaultOperationResultSchema>;
export type DialogOperationResult = z.infer<typeof DialogOperationResultSchema>;
export type DesktopStartupSettings = z.infer<typeof DesktopStartupSettingsSchema>;
export type DesktopBrowserIntegrationStatus = z.infer<typeof DesktopBrowserIntegrationStatusSchema>;
export type TrashItemSummary = z.infer<typeof TrashItemSummarySchema>;
export type LoginItemRevisionSummary = z.infer<typeof LoginItemRevisionSummarySchema>;
export type PasswordHealthReport = z.infer<typeof PasswordHealthReportSchema>;
export type BiometricStatus = z.infer<typeof BiometricStatusSchema>;
export type PinStatus = z.infer<typeof PinStatusSchema>;
export type SecuritySettings = z.infer<typeof SecuritySettingsSchema>;
export type LanNearbyDevice = z.infer<typeof LanNearbyDeviceSchema>;
export type LanPairingStatus = z.infer<typeof LanPairingStatusSchema>;
export type LanTrustedPeer = z.infer<typeof LanTrustedPeerSchema>;
export type RevealedPassword = z.infer<typeof RevealedPasswordSchema>;

export * from './service-contracts';
export * from './api-environment-contracts';
