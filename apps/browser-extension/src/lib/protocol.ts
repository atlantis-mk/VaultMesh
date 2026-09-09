import { z } from "zod";

export const PROTOCOL_VERSION = 1;
export const MAX_FIELDS_PER_FRAME = 300;
export const MAX_FIELDS_PER_REQUEST = 1_600;
export const MAX_OPTIONS_PER_FIELD = 200;
export const MAX_ASSIGNMENTS_PER_FRAME = 300;

export const AutofillItemKindSchema = z.enum(["login", "card", "identity", "secret", "ssh"]);
export const PageContextSchema = z.enum(["login", "signup", "password-change", "password-reset", "otp", "checkout", "profile", "developer-secret", "ssh-console", "unknown"]);

const boundedText = (maximum: number) => z.string().trim().max(maximum);
const httpUrlSchema = z.string().url().max(10_000).refine((value) => {
  const protocol = new URL(value).protocol;
  return protocol === "http:" || protocol === "https:";
}, "Expected an HTTP(S) URL");
const originSchema = httpUrlSchema.refine((value) => new URL(value).origin === value, "Expected an HTTP(S) origin");

export const SelectOptionSchema = z.object({
  value: boundedText(160),
  text: boundedText(160),
});

export const FieldDescriptorSchema = z.object({
  handle: z.string().uuid(),
  control: z.enum(["input", "textarea", "select", "contenteditable"]),
  inputType: boundedText(32).optional(),
  maxLength: z.number().int().min(1).max(100).optional(),
  isEmpty: z.boolean(),
  autocomplete: z.array(boundedText(64)).max(8),
  label: boundedText(240),
  name: boundedText(160),
  id: boundedText(160),
  placeholder: boundedText(160),
  context: PageContextSchema.default("unknown"),
  options: z.array(SelectOptionSchema).max(MAX_OPTIONS_PER_FIELD).optional(),
});

export const DiscoveryFrameSchema = z.object({
  frameId: z.number().int().nonnegative(),
  documentId: z.string().uuid(),
  frameOrigin: originSchema,
  fields: z.array(FieldDescriptorSchema).min(1).max(MAX_FIELDS_PER_FRAME),
});

// The content script cannot know its browser-assigned frameId. The background
// validates this response shape first, then attaches the frameId used to send
// the message before constructing a full DiscoveryFrame.
export const DiscoveryFrameResponseSchema = DiscoveryFrameSchema.omit({ frameId: true });

export const FillRequestSchema = z.object({
  version: z.literal(PROTOCOL_VERSION),
  requestId: z.string().uuid(),
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  tabId: z.number().int().nonnegative(),
  topOrigin: originSchema,
  targetOrigin: originSchema,
  targetPageUrl: httpUrlSchema,
  selectedItem: z.object({
    kind: AutofillItemKindSchema,
    id: z.string().uuid(),
    title: boundedText(256),
  }).optional(),
  frames: z.array(DiscoveryFrameSchema).min(1).max(16),
})
  .refine((value) => new URL(value.targetPageUrl).origin === value.targetOrigin, "Target page URL must match target origin")
  .refine((value) => value.frames.reduce((total, frame) => total + frame.fields.length, 0) <= MAX_FIELDS_PER_REQUEST, "Too many fields in fill request");

export const FillAssignmentSchema = z.object({
  handle: z.string().uuid(),
  value: z.string().max(10_000),
  overwrite: z.boolean(),
});

export const ApprovedFillFrameSchema = z.object({
  frameId: z.number().int().nonnegative(),
  documentId: z.string().uuid(),
  frameOrigin: originSchema,
  assignments: z.array(FillAssignmentSchema).min(1).max(MAX_ASSIGNMENTS_PER_FRAME),
});

export const ApprovedFillSchema = z.object({
  kind: z.literal("vaultmesh.approved-fill"),
  requestId: z.string().uuid(),
  tabId: z.number().int().nonnegative(),
  topOrigin: originSchema,
  expiresAt: z.string().datetime(),
  selectedItem: z.object({ kind: AutofillItemKindSchema, id: z.string().uuid(), title: boundedText(256) }).optional(),
  frames: z.array(ApprovedFillFrameSchema).min(1).max(16),
});

export const AutofillTargetSchema = z.object({ documentId: z.string().uuid(), targetId: z.string().uuid() });
export type AutofillTarget = z.infer<typeof AutofillTargetSchema>;

export const ContentMessageSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("vaultmesh.detect-page-information") }),
  z.object({ kind: z.literal("vaultmesh.scan-totp-qr") }),
  z.object({
    kind: z.literal("vaultmesh.save-page-information"),
    captureId: z.string().uuid(),
    pageUrl: httpUrlSchema,
    data: z.lazy(() => CapturedSaveDataSchema),
  }),
  z.object({
    kind: z.literal("vaultmesh.discover-fields"),
    requestId: z.string().uuid(),
    target: AutofillTargetSchema.optional(),
  }),
  z.object({ kind: z.literal("vaultmesh.autofill-rescan") }),
  z.object({
    kind: z.literal("vaultmesh.apply-assignments"),
    requestId: z.string().uuid(),
    documentId: z.string().uuid(),
    frameOrigin: originSchema,
    expiresAt: z.string().datetime(),
    selectedItem: z.object({ kind: AutofillItemKindSchema, id: z.string().uuid(), title: boundedText(256) }).optional(),
    clearBeforeFill: z.boolean().optional(),
    assignments: z.array(FillAssignmentSchema).min(1).max(MAX_ASSIGNMENTS_PER_FRAME),
  }),
]);

export const TotpQrCodeSchema = z.object({
  uri: z.string().min(1).max(10_000).refine(isSupportedTotpUri, "Expected a supported TOTP otpauth URI"),
  issuer: boundedText(256).nullable(),
  account: boundedText(2_048).nullable(),
});

function isSupportedTotpUri(value: string): boolean {
  try {
    const uri = new URL(value);
    const secret = uri.searchParams.getAll("secret");
    const algorithm = uri.searchParams.get("algorithm");
    const digits = uri.searchParams.get("digits");
    const period = uri.searchParams.get("period");
    return uri.protocol.toLocaleLowerCase() === "otpauth:"
      && uri.hostname.toLocaleLowerCase() === "totp"
      && Boolean(uri.pathname.replace(/^\//, ""))
      && secret.length === 1
      && /^[A-Z2-7]+=*$/i.test(secret[0]!.replace(/\s/g, ""))
      && (!algorithm || algorithm.toLocaleLowerCase() === "sha1")
      && (!digits || digits === "6")
      && (!period || period === "30");
  } catch {
    return false;
  }
}

export const TotpQrScanResponseSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("found"), values: z.array(TotpQrCodeSchema).min(1).max(20) }),
  z.object({ status: z.literal("empty") }),
  z.object({ status: z.literal("unsupported-page") }),
]);

export const AutofillCandidateSchema = z.object({
  id: z.string().uuid(),
  kind: AutofillItemKindSchema,
  title: boundedText(256),
  subtitle: boundedText(2048),
  matchScope: z.enum(["path", "origin", "domain"]).optional(),
  autofillOnPageLoad: z.boolean().optional(),
  masterPasswordReprompt: z.boolean().optional(),
});

export const EmailOtpCandidateSchema = z.object({
  id: z.string().uuid(),
  code: z.string().regex(/^(?=.*\d)[A-Za-z0-9]{4,8}$/),
  sourceDomain: z.string().min(1).max(253),
  receivedAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().nonnegative(),
});

const selectedItemSchema = z.object({
    kind: AutofillItemKindSchema,
    id: z.string().uuid(),
    title: boundedText(256),
    masterPasswordReprompt: z.boolean().optional(),
});

const capturedLoginSchema = z.object({
  username: z.string().max(2_048),
  password: z.string().min(1).max(10_000),
  loginId: z.string().uuid().optional(),
  title: boundedText(256).min(1).optional(),
  url: httpUrlSchema.nullable().optional(),
  totpSecret: z.string().min(1).max(10_000).nullable().optional(),
  additionalUrls: z.array(httpUrlSchema).max(20).optional(),
  customFields: z.array(z.object({ label: boundedText(256).min(1), value: z.string().max(10_000) })).max(50).optional(),
});
const capturedIdentitySchema = z.object({
  identityId: z.string().uuid().optional(),
  title: boundedText(256).min(1),
  firstName: boundedText(256).nullable(), middleName: boundedText(256).nullable(), lastName: boundedText(256).nullable(),
  birthDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable(),
  emails: z.array(z.object({ label: boundedText(256), value: boundedText(2_048).min(1), preferred: z.boolean() })).max(20),
  phones: z.array(z.object({ label: boundedText(256), value: boundedText(2_048).min(1), preferred: z.boolean() })).max(20),
  addresses: z.array(z.object({
    label: boundedText(256), addressLine1: boundedText(512).min(1), addressLine2: boundedText(10_000).nullable(),
    city: boundedText(256).nullable(), region: boundedText(256).nullable(), postalCode: boundedText(256).nullable(),
    countryCode: z.string().regex(/^[A-Z]{2}$/).nullable(), country: boundedText(256).nullable(), preferred: z.boolean(),
  })).max(20),
  organization: boundedText(256).nullable(), department: boundedText(256).nullable(), jobTitle: boundedText(256).nullable(),
  website: httpUrlSchema.nullable(),
});
const capturedCardSchema = z.object({
  cardId: z.string().uuid().optional(),
  title: boundedText(256).min(1), cardholderName: boundedText(256).min(1), cardNumber: z.string().regex(/^\d{12,19}$/),
  expirationMonth: z.number().int().min(1).max(12), expirationYear: z.number().int().min(1_000).max(9_999),
  securityCode: z.string().regex(/^\d{3,4}$/).nullable(), pin: z.string().regex(/^\d{4,12}$/).nullable().optional(),
  issuer: boundedText(256).nullable().optional(), network: boundedText(256).nullable().optional(), billingAddress: boundedText(10_000).nullable(),
});
const capturedSecretSchema = z.object({
  title: boundedText(256).min(1),
  kind: z.enum(["api-key", "access-token", "authenticator-key", "client-secret", "webhook-secret", "database-credential", "recovery-codes", "certificate", "software-license", "identity-document", "secure-note", "crypto-wallet", "other"]),
  secret: z.string().min(1).max(10_000),
  provider: boundedText(256).nullable(),
  account: boundedText(256).nullable(),
  environment: boundedText(256).nullable(),
  scopes: z.array(boundedText(256).min(1)).max(50),
  expiresAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable(),
  website: httpUrlSchema.nullable(),
});
const capturedSshSchema = z.object({
  title: boundedText(256).min(1),
  host: boundedText(256).nullable(),
  port: z.number().int().min(1).max(65_535),
  username: boundedText(2_048),
  password: z.string().min(1).max(10_000).nullable(),
  publicKey: z.string().min(1).max(200_000).nullable(),
  privateKey: z.string().min(1).max(200_000).nullable(),
  keyPassphrase: z.string().min(1).max(10_000).nullable(),
}).refine((data) => Boolean(data.password || data.publicKey || data.privateKey), "SSH capture requires key or password material");

export const CapturedSaveDataSchema = z.object({
  login: capturedLoginSchema.optional(),
  identity: capturedIdentitySchema.optional(),
  card: capturedCardSchema.optional(),
  secrets: z.array(capturedSecretSchema).max(100).optional(),
  sshCredentials: z.array(capturedSshSchema).max(50).optional(),
}).refine((data) => Boolean(data.login || data.identity || data.card || data.secrets?.length || data.sshCredentials?.length), "Capture must contain saveable data");

export const PageInformationDetectionResponseSchema = z.discriminatedUnion("status", [
  z.object({
    status: z.literal("detected"),
    captureId: z.string().uuid(),
    pageUrl: httpUrlSchema,
    pageTitle: boundedText(256),
    data: CapturedSaveDataSchema,
    ignoredSensitiveFields: z.array(boundedText(64)).max(20),
  }),
  z.object({ status: z.literal("empty"), pageUrl: httpUrlSchema }),
  z.object({ status: z.literal("unsupported-page") }),
]);

export const PageInformationSaveResponseSchema = z.object({
  status: z.enum(["saved", "unchanged", "account-check-failed", "save-check-failed", "expired", "failed", "unsupported-page"]),
  failedItem: boundedText(64).optional(),
  errorCode: boundedText(64).optional(),
  errorMessage: boundedText(256).optional(),
});

export const PopupMessageSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("vaultmesh.popup-workspace-cache.get") }),
  z.object({ kind: z.literal("vaultmesh.save-capture-popup.get") }),
  z.object({
    kind: z.literal("vaultmesh.save-capture-popup.decision"),
    captureId: z.string().uuid(),
    decision: z.enum(["save", "ignore"]),
  }),
  z.object({ kind: z.literal("vaultmesh.save-capture-window.get") }),
  z.object({ kind: z.literal("vaultmesh.save-capture-window.decision"), decision: z.enum(["save", "ignore"]) }),
  z.object({
    kind: z.literal("vaultmesh.start-fill"),
    selectedItem: selectedItemSchema.optional(),
    masterPassword: z.string().min(8).max(1_024).optional(),
    fillConfirmationToken: z.string().uuid().optional(),
  }),
  z.object({ kind: z.literal("vaultmesh.fill-confirmation.get") }),
  z.object({ kind: z.literal("vaultmesh.fill-confirmation.cancel"), fillConfirmationToken: z.string().uuid() }),
  z.object({ kind: z.literal("vaultmesh.autofill-state") }),
  z.object({ kind: z.literal("vaultmesh.open-unlock") }),
  z.object({ kind: z.literal("vaultmesh.security-policy.updated") }),
  z.object({ kind: z.literal("vaultmesh.email-otp-fill"), candidateId: z.string().uuid() }),
  z.object({ kind: z.literal("vaultmesh.autofill-page-ready"), documentId: z.string().uuid(), signature: boundedText(512), pageContext: PageContextSchema, target: AutofillTargetSchema.optional() }),
  z.object({ kind: z.literal("vaultmesh.otp-watch-requested") }),
  z.object({ kind: z.literal("vaultmesh.autofill-candidates"), fieldKind: AutofillItemKindSchema, pageContext: PageContextSchema }),
  z.object({ kind: z.literal("vaultmesh.email-otp-select"), candidateId: z.string().uuid(), target: AutofillTargetSchema.optional() }),
  z.object({
    kind: z.literal("vaultmesh.autofill-select"),
    selectedItem: selectedItemSchema,
    replaceExistingAccount: z.boolean().optional(),
    target: AutofillTargetSchema.optional(),
  }),
  z.object({ kind: z.literal("vaultmesh.save-capture-pending") }),
  z.object({
    kind: z.literal("vaultmesh.save-capture-decision"),
    captureId: z.string().uuid(),
    decision: z.enum(["save", "ignore"]),
  }),
  z.object({
    kind: z.literal("vaultmesh.save-capture"),
    captureId: z.string().uuid(),
    pageUrl: z.string().url().max(10_000),
    pageContext: PageContextSchema,
    data: CapturedSaveDataSchema,
  }),
  z.object({
    kind: z.literal("vaultmesh.save-capture-confirmed"),
    captureId: z.string().uuid(),
    pageUrl: httpUrlSchema,
    data: CapturedSaveDataSchema,
  }),
  z.object({ kind: z.literal("vaultmesh.account-stage"), pageUrl: z.string().url().max(10_000), username: z.string().min(1).max(2_048) }),
]);

export const SaveCaptureQueuedResponseSchema = z.object({
  status: z.literal("queued"),
  captureId: z.string().uuid(),
  hostname: boundedText(256),
  labels: z.array(boundedText(64)).min(1).max(5),
  update: z.boolean(),
  expiresAt: z.number().int().positive(),
  actions: z.object({
    login: z.enum(["new", "update"]).optional(),
    identity: z.enum(["new", "update"]).optional(),
    card: z.enum(["new", "update"]).optional(),
    secret: z.enum(["new", "update"]).optional(),
    ssh: z.enum(["new", "update"]).optional(),
  }).optional(),
});

export const SaveCapturePendingResponseSchema = z.union([
  SaveCaptureQueuedResponseSchema,
  z.object({ status: z.literal("preparing"), captureId: z.string().uuid() }),
  z.object({ status: z.literal("none") }),
]);

export const SaveCaptureReadyMessageSchema = z.object({
  kind: z.literal("vaultmesh.save-capture-ready"),
  prompt: SaveCaptureQueuedResponseSchema,
});

export const SaveCaptureDecisionResponseSchema = z.object({
  status: z.enum(["saved", "discarded", "expired", "failed", "unsupported-page"]),
});

export const AutofillAvailabilityResponseSchema = z.object({
  status: z.enum(["ready", "locked", "unavailable"]),
});

export const AutofillCandidatesResponseSchema = z.object({
  status: z.enum(["ready", "locked", "unavailable", "unsupported-page"]),
  candidates: z.array(AutofillCandidateSchema).max(200),
  emailOtpCandidates: z.array(EmailOtpCandidateSchema).max(20).optional(),
});

export type ContentMessage = z.infer<typeof ContentMessageSchema>;
export type PopupMessage = z.infer<typeof PopupMessageSchema>;
export type DiscoveryFrame = z.infer<typeof DiscoveryFrameSchema>;
export type FieldDescriptor = z.infer<typeof FieldDescriptorSchema>;
export type FillRequest = z.infer<typeof FillRequestSchema>;
export type ApprovedFill = z.infer<typeof ApprovedFillSchema>;
export type AutofillCandidate = z.infer<typeof AutofillCandidateSchema>;
export type EmailOtpCandidate = z.infer<typeof EmailOtpCandidateSchema>;
export type InlineAutofillCandidate = AutofillCandidate | (EmailOtpCandidate & {
  kind: "email-otp";
  title: string;
  subtitle: string;
});
export type AutofillItemKind = z.infer<typeof AutofillItemKindSchema>;
export type PageContext = z.infer<typeof PageContextSchema>;
export type PageInformationDetectionResponse = z.infer<typeof PageInformationDetectionResponseSchema>;
export type TotpQrCode = z.infer<typeof TotpQrCodeSchema>;
export type SaveCaptureQueuedResponse = z.infer<typeof SaveCaptureQueuedResponseSchema>;
