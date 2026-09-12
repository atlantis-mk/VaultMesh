import { CipherType, FieldType } from "@bitwarden/common/vault/enums";
import { FieldView } from "@bitwarden/common/vault/models/view/field.view";
import { SshKeyView } from "@bitwarden/common/vault/models/view/ssh-key.view";
import { UriMatchStrategy } from "@bitwarden/common/models/domain/domain-service";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { CardView } from "@bitwarden/common/vault/models/view/card.view";
import { IdentityView } from "@bitwarden/common/vault/models/view/identity.view";
import { AutofillScriptGenerator } from "../autofill/services/autofill-script-generator";
import type AutofillPageDetails from "../autofill/models/autofill-page-details";
import type AutofillField from "../autofill/models/autofill-field";
import type AutofillScript from "../autofill/models/autofill-script";
import { NativeItemSourceSchema, type NativeItemSource } from "./vendor/browser-native-item-plan";
import { InlineMenuFieldQualificationService } from "../autofill/services/inline-menu-field-qualification.service";
import { CreditCardAutoFillConstants, IdentityAutoFillConstants } from "../autofill/services/autofill-constants";
import { fieldContainsKeyword, KeywordMatchMode } from "../autofill/utils/qualification";
import { excludedMetadata } from "./native-fill-contracts";

export type NativeItemKind = "card" | "identity" | "ssh" | "secret";
// VaultMesh-only data roles use the original exact custom-field matcher, never
// generic password/key tokens or a form-wide role inferred from nearby text.
const customSources: Partial<Record<NativeItemSource, string[]>> = {
  "ssh:title": ["sshKeyTitle", "ssh_key_title", "SSH key title"],
  "ssh:host": ["sshHost", "ssh_host", "ssh-host", "SSH host", "SSH 主机"],
  "ssh:port": ["sshPort", "ssh_port", "ssh-port", "SSH port", "SSH 端口"],
  "ssh:username": ["sshUsername", "ssh_username", "ssh-user", "SSH username", "SSH 用户名"],
  "ssh:password": ["sshPassword", "ssh_password", "ssh-password", "SSH password", "SSH 密码"],
  "ssh:privateKey": ["sshPrivateKey", "ssh_private_key", "ssh-private-key", "SSH private key", "SSH 私钥"],
  "ssh:keyPassphrase": ["sshKeyPassphrase", "ssh_key_passphrase", "ssh-key-passphrase", "SSH key passphrase", "SSH 私钥口令"],
  "secret:api-key": ["apiKey", "api_key", "api-key", "API key", "API 密钥"],
  "secret:access-token": ["accessToken", "access_token", "access-token", "Access token", "访问令牌"],
  "secret:authenticator-key": ["totpSecret", "totp_secret", "totp-secret", "Authenticator key", "身份验证器密钥"],
  "secret:client-secret": ["clientSecret", "client_secret", "client-secret", "Client secret", "客户端密钥"],
  "secret:webhook-secret": ["webhookSecret", "webhook_secret", "webhook-secret", "Webhook secret"],
  "secret:database-credential": ["databaseCredential", "database_credential", "Database credential"],
  "secret:recovery-codes": ["recoveryCodes", "recovery_codes", "Recovery codes", "恢复码"],
  "secret:certificate": ["clientCertificate", "client_certificate", "Client certificate", "客户端证书"],
  "secret:software-license": ["licenseKey", "license_key", "License key", "软件许可证"],
  "secret:identity-document": ["identityDocument", "identity_document", "Identity document"],
  "secret:secure-note": ["secureNote", "secure_note", "Secure note"],
  "secret:crypto-wallet": ["walletRecoveryPhrase", "wallet_recovery_phrase", "Wallet recovery phrase"],
  "secret:other": ["serviceSecret", "service_secret", "Service secret", "服务密钥"],
  "secret:account": ["secretAccount", "secret_account", "Secret account"],
  "secret:provider": ["secretProvider", "secret_provider", "Secret provider"],
};
const qualification = new InlineMenuFieldQualificationService(true);
export function qualifiedNativeItemSource(field: AutofillField, source: NativeItemSource): boolean {
  const methods: Partial<Record<NativeItemSource, (field: AutofillField) => boolean>> = {
    "card:cardholderName": qualification.isFieldForCardholderName, "card:number": qualification.isFieldForCardNumber,
    "card:code": qualification.isFieldForCardCvv, "card:exp": qualification.isFieldForCardExpirationDate,
    "card:expMonth": qualification.isFieldForCardExpirationMonth, "card:expYear": qualification.isFieldForCardExpirationYear,
    "identity:firstName": qualification.isFieldForIdentityFirstName, "identity:middleName": qualification.isFieldForIdentityMiddleName,
    "identity:lastName": qualification.isFieldForIdentityLastName, "identity:fullName": qualification.isFieldForIdentityFullName,
    "identity:email": qualification.isFieldForIdentityEmail, "identity:address1": qualification.isFieldForIdentityAddress1,
    "identity:address2": qualification.isFieldForIdentityAddress2, "identity:city": qualification.isFieldForIdentityCity,
    "identity:state": qualification.isFieldForIdentityState, "identity:country": qualification.isFieldForIdentityCountry,
    "identity:postalCode": qualification.isFieldForIdentityPostalCode, "identity:phone": qualification.isFieldForIdentityPhone,
    "identity:company": qualification.isFieldForIdentityCompany,
  };
  if (source === "card:brand") return fieldContainsKeyword(field, CreditCardAutoFillConstants.CardBrandFieldNames, KeywordMatchMode.MatchesToken);
  if (source === "identity:fullAddress") return fieldContainsKeyword(field, IdentityAutoFillConstants.AddressFieldNames, KeywordMatchMode.MatchesToken);
  return methods[source]?.(field) ?? false;
}
class RemoteItemPlanner extends AutofillScriptGenerator {
  matches(field: AutofillField, names: string[]): boolean {
    return this.findMatchingFieldIndex(field, names.map((name) => name.toLowerCase())) >= 0;
  }
  protected override makeScriptActionWithValue(script: AutofillScript, value: string, field: AutofillField, filled: Record<string, AutofillField>): void {
    if (NativeItemSourceSchema.safeParse(value).success) { filled[field.opid] = field; AutofillScriptGenerator.fillByOpid(script, field, value); }
    else super.makeScriptActionWithValue(script, value, field, filled);
  }
}
/** Reserved credential fields must never become implicit Login password targets. */
export function credentialCustomSources(field: AutofillField): NativeItemSource[] {
  const planner = new RemoteItemPlanner();
  return Object.entries(customSources).filter(([, aliases]) => planner.matches(field, aliases)).map(([source]) => NativeItemSourceSchema.parse(source));
}
function cipherFor(kind: NativeItemKind): CipherView {
  const cipher = new CipherView();
  cipher.type = kind === "card" ? CipherType.Card : kind === "ssh" ? CipherType.SshKey : CipherType.Identity;
  cipher.card = new CardView(); cipher.identity = new IdentityView();
  cipher.sshKey = new SshKeyView();
  return cipher;
}

/** Calls the original matching branches with symbolic fields, not a second classifier. */
export async function planNativeItem(page: AutofillPageDetails, kind: NativeItemKind) {
  if (kind === "ssh" || kind === "secret") return planNativeCredential(page, kind);
  const cipher = cipherFor(kind);
  if (kind === "identity") for (const source of NativeItemSourceSchema.options) {
    if (!source.startsWith("identity:")) continue;
    const key = source.slice(9);
    if (key !== "fullName" && key !== "fullAddress") (cipher.identity as unknown as Record<string, string>)[key] = source;
  }
  const script = await new RemoteItemPlanner().generateFillScript(page, {
    cipher, remoteTotpPlanning: true, remoteItemPlanning: true, autoSubmitLogin: false, onlyEmptyFields: true,
    skipUsernameOnlyFill: false, fillNewPassword: false, allowTotpAutofill: false, canAccessTotp: false, tabUrl: page.url, defaultUriMatch: UriMatchStrategy.Domain,
  });
  const result = new Map<string, NativeItemSource>();
  for (const [action, opid, value] of script?.script ?? []) {
    if (action !== "fill_by_opid") continue;
    const source = NativeItemSourceSchema.safeParse(value);
    if (!source.success || !source.data.startsWith(`${kind}:`) || result.has(opid)) throw new Error("invalid-fill-plan");
    const field = page.fields.find((field) => field.opid === opid);
    if (field && qualifiedNativeItemSource(field, source.data)) result.set(opid, source.data);
  }
  return result;
}

/** Re-run original formatting on ONE approved field using ONLY that source's value. */
export async function formatNativeItem(page: AutofillPageDetails, opid: string, source: NativeItemSource, value: string): Promise<string | null> {
  const field = page.fields.find((entry) => entry.opid === opid);
  if (!field || !NativeItemSourceSchema.safeParse(source).success) return null;
  if (source.startsWith("ssh:") || source.startsWith("secret:")) {
    const plan = await planNativeCredential(page, source.startsWith("ssh:") ? "ssh" : "secret");
    // No value-dependent transformation for these sources. The original executor
    // applies the approved value; re-planning here still uses metadata only.
    return plan.get(opid) === source ? value : null;
  }
  const kind = source.startsWith("card:") ? "card" : "identity";
  const cipher = cipherFor(kind);
  const key = source.slice(kind.length + 1);
  const record = (kind === "card" ? cipher.card : cipher.identity) as unknown as Record<string, string>;
  if (source === "card:exp") {
    const match = /^(\d{1,2})\/(\d{4})$/.exec(value);
    if (!match) return null;
    record.expMonth = match[1]; record.expYear = match[2];
  } else record[key === "fullName" ? "firstName" : key === "fullAddress" ? "address1" : key] = value;
  try {
    const script = await new AutofillScriptGenerator().generateFillScript({ ...page, fields: [field] }, {
      cipher, remoteTotpPlanning: true, autoSubmitLogin: false, onlyEmptyFields: true,
      skipUsernameOnlyFill: false, fillNewPassword: false, allowTotpAutofill: false, canAccessTotp: false, tabUrl: page.url, defaultUriMatch: UriMatchStrategy.Domain,
    });
    const actions = (script?.script ?? []).filter(([action, target]) => action === "fill_by_opid" && target === opid);
    return actions.length === 1 ? actions[0][2] ?? null : null;
  } finally { for (const key of Object.keys(record)) if (typeof record[key] === "string") record[key] = ""; }
}

async function planNativeCredential(page: AutofillPageDetails, kind: "ssh" | "secret") {
  const result = new Map<string, NativeItemSource>();
  const planner = new RemoteItemPlanner();
  const usable = page.fields.filter((field) => field.viewable && !field.disabled && !field.readonly
    && !excludedMetadata([field.htmlID, field.htmlName, field.title, field.placeholder, field["label-tag"], field["label-aria"], field["label-left"]].join(" "))
    && (field.tagName === "textarea" || field.tagName === "input" && ["text", "password", "email", "tel", "number"].includes(field.type))
    && !/(?:^|\s)(?:new-password|one-time-code)(?:\s|$)/.test(field.autoCompleteType ?? ""));
  const options = { remoteTotpPlanning: true, autoSubmitLogin: false, onlyEmptyFields: true,
    skipUsernameOnlyFill: false, fillNewPassword: false, allowTotpAutofill: false, canAccessTotp: false, tabUrl: page.url, defaultUriMatch: UriMatchStrategy.Domain };
  for (const field of usable) {
    const matches = credentialCustomSources(field);
    if (matches.length !== 1 || !matches[0].startsWith(`${kind}:`)) continue;
    const source = matches[0]; const aliases = customSources[source]!;
    if (field.type === "number" && source !== "ssh:port") continue;
    const cipher = cipherFor("identity");
    cipher.fields = aliases.map((name) => { const entry = new FieldView(); entry.name = name; entry.type = FieldType.Hidden; entry.value = source; return entry; });
    const script = await planner.generateFillScript({ ...page, fields: [field] }, { ...options, cipher });
    if (script?.script.some(([action, opid, value]) => action === "fill_by_opid" && opid === field.opid && value === source)) result.set(field.opid, NativeItemSourceSchema.parse(source));
  }
  if (kind === "ssh") {
    // Run upstream SSH public-key/title matching separately for each real form.
    // A generic key textarea needs an explicit public-key/algorithm signal.
    for (const form of new Set(usable.map((field) => field.form))) {
      const fields = usable.filter((field) => field.form === form && !credentialCustomSources(field).length);
      const publicFields = fields.filter((field) => field.tagName === "textarea"
        && qualification.isFieldForSshKeyForm(field, { ...page, fields })
        && fieldContainsKeyword(field, ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2", "publickey", "public_key", "public key", "authorized_keys", "公钥"], KeywordMatchMode.MatchesToken));
      if (!publicFields.length) continue;
      const cipher = cipherFor("ssh"); cipher.name = "ssh:title"; cipher.sshKey.publicKey = "ssh:publicKey";
      const script = await planner.generateFillScript({ ...page, fields: fields.filter((field) => field.tagName !== "textarea" || publicFields.includes(field)) }, { ...options, cipher });
      for (const [action, opid, source] of script?.script ?? []) {
        const field = fields.find((field) => field.opid === opid);
        if (action === "fill_by_opid" && field && (source === "ssh:publicKey" && publicFields.includes(field)
          || source === "ssh:title" && !!field.form && qualification.isFieldForSshKeyForm(field, { ...page, fields: [...publicFields, field] }))) result.set(opid, source as NativeItemSource);
      }
    }
  }
  return result;
}
