import { CipherType } from "@bitwarden/common/vault/enums";
import { UriMatchStrategy } from "@bitwarden/common/models/domain/domain-service";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { CardView } from "@bitwarden/common/vault/models/view/card.view";
import { IdentityView } from "@bitwarden/common/vault/models/view/identity.view";
import { AutofillScriptGenerator } from "../autofill/services/autofill-script-generator";
import type AutofillPageDetails from "../autofill/models/autofill-page-details";
import { NativeItemSourceSchema, type NativeItemSource } from "./vendor/browser-native-item-plan";

export type NativeItemKind = "card" | "identity";
function cipherFor(kind: NativeItemKind): CipherView {
  const cipher = new CipherView();
  cipher.type = kind === "card" ? CipherType.Card : CipherType.Identity;
  cipher.card = new CardView(); cipher.identity = new IdentityView();
  return cipher;
}

/** Calls the original matching branches with symbolic fields, not a second classifier. */
export async function planNativeItem(page: AutofillPageDetails, kind: NativeItemKind) {
  const cipher = cipherFor(kind);
  if (kind === "identity") for (const source of NativeItemSourceSchema.options) {
    if (!source.startsWith("identity:")) continue;
    const key = source.slice(9);
    if (key !== "fullName" && key !== "fullAddress") (cipher.identity as unknown as Record<string, string>)[key] = source;
  }
  const script = await new AutofillScriptGenerator().generateFillScript(page, {
    cipher, remoteTotpPlanning: true, remoteItemPlanning: true, autoSubmitLogin: false, onlyEmptyFields: true,
    skipUsernameOnlyFill: false, fillNewPassword: false, allowTotpAutofill: false, canAccessTotp: false, tabUrl: page.url, defaultUriMatch: UriMatchStrategy.Domain,
  });
  const result = new Map<string, NativeItemSource>();
  for (const [action, opid, value] of script?.script ?? []) {
    if (action !== "fill_by_opid") continue;
    const source = NativeItemSourceSchema.safeParse(value);
    if (!source.success || !source.data.startsWith(`${kind}:`) || result.has(opid)) throw new Error("invalid-fill-plan");
    result.set(opid, source.data);
  }
  return result;
}

/** Re-run original formatting on ONE approved field using ONLY that source's value. */
export async function formatNativeItem(page: AutofillPageDetails, opid: string, source: NativeItemSource, value: string): Promise<string | null> {
  const field = page.fields.find((entry) => entry.opid === opid);
  if (!field || !NativeItemSourceSchema.safeParse(source).success) return null;
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
