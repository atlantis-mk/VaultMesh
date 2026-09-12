import { ManagedDraft } from "./managed-draft";
import { CapturedItemValuesSchema } from "./native-capture-contracts";
import { SecretItemKindSchema } from "./vendor/model-contracts";

/** Update only captured sources; retain all other fields and every collection entry. */
export function applyCapturedItem(draft: ManagedDraft, raw: unknown): void {
  const rows = CapturedItemValuesSchema.parse(raw);
  if (!rows.every((row) => row.source.startsWith(`${draft.kind}:`))) throw new Error("capture-kind-mismatch");
  const values = new Map(rows.map((row) => [row.source.split(":")[1], row.value]));
  if (draft.kind === "ssh") {
    const key = ["publicKey", "privateKey", "keyPassphrase"].some((source) => values.has(source));
    const account = ["host", "port", "username", "password"].some((source) => values.has(source));
    if (key && account || !draft.id && !key && !account) throw new Error("ambiguous-ssh-capture");
    const recordKind = key ? "key" : account ? "account" : draft.data.recordKind;
    if (draft.id && recordKind !== draft.data.recordKind) throw new Error("capture-kind-mismatch");
    if (!draft.id) draft.data.recordKind = recordKind;
    for (const source of ["title", "host", "username", "password", "publicKey", "privateKey", "keyPassphrase"]) {
      if (values.has(source)) draft.data[source] = values.get(source);
    }
    if (values.has("port")) {
      if (!/^\d{1,5}$/.test(values.get("port")!)) throw new Error("invalid-ssh-port");
      draft.data.port = Number(values.get("port"));
    }
    return;
  }
  if (draft.kind === "secret") {
    const secrets = rows.filter((row) => SecretItemKindSchema.safeParse(row.source.slice(7)).success);
    if (secrets.length > 1 || !draft.id && secrets.length !== 1) throw new Error("ambiguous-secret-capture");
    if (secrets.length) {
      const kind = SecretItemKindSchema.parse(secrets[0].source.slice(7));
      if (draft.id && draft.data.kind !== kind) throw new Error("capture-kind-mismatch");
      if (!draft.id) { draft.data.kind = kind; draft.data.masterPasswordReprompt = false; }
      draft.data.secret = secrets[0].value;
    }
    for (const key of ["account", "provider"]) if (values.has(key)) draft.data[key] = values.get(key);
    return;
  }
  if (draft.kind === "card") {
    if (!draft.id && (!values.has("number") || !values.has("exp") && !(values.has("expMonth") && values.has("expYear")))) throw new Error("incomplete-card-capture");
    for (const [source, key] of [["cardholderName", "cardholderName"], ["number", "cardNumber"], ["code", "securityCode"], ["brand", "network"]]) {
      if (values.has(source)) draft.data[key] = values.get(source);
    }
    if (values.has("exp")) {
      const value = values.get("exp")!.trim();
      const match = /^(\d{1,2})\s*\/\s*(\d{2}|\d{4})$/.exec(value);
      const monthInput = /^(\d{4})-(\d{2})$/.exec(value);
      if (!match && !monthInput) throw new Error("invalid-expiry");
      values.set("expMonth", match ? match[1] : monthInput![2]);
      values.set("expYear", match ? match[2] : monthInput![1]);
    }
    if (values.has("expMonth")) draft.data.expirationMonth = Number(values.get("expMonth"));
    if (values.has("expYear")) { const year = values.get("expYear")!; draft.data.expirationYear = Number(year.length === 2 ? `${String(new Date().getFullYear()).slice(0, 2)}${year}` : year); }
    return;
  }
  if (draft.kind !== "identity") throw new Error("capture-kind-mismatch");
  for (const key of ["firstName", "middleName", "lastName"]) if (values.has(key)) draft.data[key] = values.get(key);
  if (values.has("fullName")) {
    if (["firstName", "middleName", "lastName"].some((key) => values.has(key))) throw new Error("ambiguous-name");
    // Do not infer culturally dependent name splitting.
    draft.data.firstName = values.get("fullName"); draft.data.middleName = draft.data.lastName = "";
  }
  if (values.has("company")) draft.data.organization = values.get("company");
  for (const [source, collection] of [["email", "emails"], ["phone", "phones"]] as const) {
    if (!values.has(source)) continue;
    const entries = draft.data[collection] as Record<string, unknown>[];
    if (!entries.length) draft.add(collection);
    const entry = entries.find((row) => row.preferred) ?? entries[0];
    entry.value = values.get(source);
  }
  const addressKeys = [["address1", "addressLine1"], ["address2", "addressLine2"], ["city", "city"], ["state", "region"], ["postalCode", "postalCode"]];
  if (values.has("fullAddress") && (values.has("address1") || values.has("address2"))) throw new Error("ambiguous-address");
  if (addressKeys.some(([key]) => values.has(key)) || values.has("country") || values.has("fullAddress")) {
    const entries = draft.data.addresses as Record<string, unknown>[];
    if (!entries.length) draft.add("addresses");
    const entry = entries.find((row) => row.preferred) ?? entries[0];
    for (const [source, key] of addressKeys) if (values.has(source)) entry[key] = values.get(source);
    if (values.has("fullAddress")) { entry.addressLine1 = values.get("fullAddress"); entry.addressLine2 = ""; }
    if (values.has("country")) { const country = values.get("country")!; entry.countryCode = /^[a-z]{2}$/i.test(country) ? country.toUpperCase() : null; entry.country = country; }
  }
}
