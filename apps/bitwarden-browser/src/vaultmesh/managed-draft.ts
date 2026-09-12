import { MANAGED_ITEMS, type ManagedKind } from "./managed-items";
import { SecretItemKindSchema } from "./vendor/model-contracts";
import { createVaultMeshUuid } from "./uuid";

export type EditorField = { key: string; label: string; type?: "number" | "checkbox" | "password" | "multiline" | "select";
  options?: readonly string[]; nullable?: boolean; clear?: string };
const optional = (key: string, label: string): EditorField => ({ key, label, nullable: true });
const secret = (key: string, label: string, clear?: string, multiline = false): EditorField => ({ key, label, type: multiline ? "multiline" : "password", nullable: true, clear });
const common: EditorField[] = [{ key: "title", label: "名称" }, optional("folder", "文件夹"),
  { ...optional("notes", "备注"), type: "multiline" }, { key: "favorite", label: "收藏", type: "checkbox" }];
const reprompt: EditorField = { key: "masterPasswordReprompt", label: "读取秘密前重新验证主密码", type: "checkbox" };
export const MANAGED_FIELDS: Record<ManagedKind, EditorField[]> = {
  card: [...common, { key: "cardholderName", label: "持卡人" }, secret("cardNumber", "卡号（编辑时留空保留）"),
    { key: "expirationMonth", label: "到期月份", type: "number" }, { key: "expirationYear", label: "到期年份", type: "number" },
    secret("securityCode", "安全码", "clearSecurityCode"), secret("pin", "卡片 PIN", "clearPin"),
    optional("issuer", "发卡机构"), optional("network", "卡组织"), optional("billingAddress", "账单地址"), reprompt],
  identity: [...common, optional("firstName", "名"), optional("middleName", "中间名"), optional("lastName", "姓"),
    optional("birthDate", "出生日期 YYYY-MM-DD"), optional("organization", "组织"), optional("department", "部门"),
    optional("jobTitle", "职位"), optional("website", "网站")],
  ssh: [...common, { key: "recordKind", label: "记录类型", type: "select", options: ["account", "key"] },
    optional("host", "主机"), { key: "port", label: "端口", type: "number" }, { key: "username", label: "用户名" },
    secret("password", "密码", "clearPassword"), secret("publicKey", "公钥", "clearPublicKey", true),
    secret("privateKey", "私钥", "clearPrivateKey", true), secret("keyPassphrase", "私钥口令", "clearKeyPassphrase"), reprompt],
  secret: [...common, { key: "kind", label: "密钥类型", type: "select", options: SecretItemKindSchema.options },
    secret("secret", "受保护值（编辑时留空保留）", undefined, true), optional("provider", "提供方"), optional("account", "账号"),
    optional("environment", "环境"), optional("expiresAt", "到期日 YYYY-MM-DD"), optional("website", "网站"), reprompt],
};
export const IDENTITY_COLLECTIONS = ["emails", "phones", "addresses"] as const;
export type IdentityCollection = typeof IDENTITY_COLLECTIONS[number];
export const ADDRESS_FIELDS: EditorField[] = [{ key: "addressLine1", label: "地址第一行" }, optional("addressLine2", "地址第二行"),
  optional("city", "城市"), optional("region", "地区/省"), optional("postalCode", "邮编"), optional("countryCode", "国家代码（两位）"), optional("country", "国家")];

/** All fields live in this editor instance. Existing protected values are never requested. */
export class ManagedDraft {
  readonly fields: EditorField[];
  readonly data: Record<string, any> = {};
  readonly id?: string;
  readonly maskedNumber: string;
  scopes = "";
  private disposed = false;
  constructor(readonly kind: ManagedKind, detail?: Record<string, unknown>) {
    this.fields = MANAGED_FIELDS[kind];
    this.id = typeof detail?.id === "string" ? detail.id : undefined;
    this.maskedNumber = typeof detail?.maskedNumber === "string" ? detail.maskedNumber : "";
    for (const field of this.fields) {
      // Protected fields have no detail representation and always start empty.
      this.data[field.key] = detail?.[field.key] ?? (field.type === "checkbox" ? false : field.key === "port" ? 22
        : field.key === "expirationMonth" ? 1 : field.key === "expirationYear" ? new Date().getFullYear()
        : field.key === "recordKind" ? "account" : field.key === "kind" ? "api-key" : "");
      if (field.clear && this.id) this.data[field.clear] = false;
    }
    if (kind === "identity") for (const key of IDENTITY_COLLECTIONS) this.data[key] = ((detail?.[key] ?? []) as Record<string, unknown>[]).map((row) => ({ ...row }));
    if (kind === "secret") this.scopes = (detail?.scopes as string[] | undefined ?? []).join("\n");
  }
  add(collection: IdentityCollection): void {
    if (this.disposed || this.kind !== "identity" || this.data[collection].length >= 20) return;
    this.data[collection].push({ id: createVaultMeshUuid(), label: "", preferred: this.data[collection].length === 0,
      ...(collection === "addresses" ? Object.fromEntries(ADDRESS_FIELDS.map((field) => [field.key, ""])) : { value: "" }) });
  }
  remove(collection: IdentityCollection, index: number): void {
    const row = this.data[collection]?.[index];
    if (row) { for (const key of Object.keys(row)) row[key] = ""; this.data[collection].splice(index, 1); }
  }
  toInput(): Record<string, unknown> {
    if (this.disposed) throw new Error("expired-draft");
    const input: Record<string, unknown> = this.id ? { id: this.id } : {};
    for (const field of this.fields) {
      const value = this.data[field.key];
      input[field.key] = field.type === "number" ? Number(value) : field.nullable && value === "" ? null : value;
      if (field.clear && this.id) input[field.clear] = this.data[field.clear] === true;
    }
    if (this.kind === "identity") {
      for (const collection of IDENTITY_COLLECTIONS) {
        input[collection] = this.data[collection].map((row: Record<string, unknown>) => {
          const copy = { ...row };
          if (collection === "addresses") for (const field of ADDRESS_FIELDS) if (field.nullable && copy[field.key] === "") copy[field.key] = null;
          return copy;
        });
      }
    }
    if (this.kind === "secret") input.scopes = this.scopes.split(/\r?\n/).map((scope) => scope.trim()).filter(Boolean);
    const definition = MANAGED_ITEMS[this.kind];
    return (this.id ? definition.update : definition.input).strict().parse(input);
  }
  clear(): void {
    this.disposed = true;
    this.scopes = "";
    for (const key of Object.keys(this.data)) {
      if (Array.isArray(this.data[key])) for (const row of this.data[key]) for (const field of Object.keys(row)) row[field] = "";
      this.data[key] = "";
    }
  }
}
