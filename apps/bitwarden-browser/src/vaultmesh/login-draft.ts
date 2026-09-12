import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { FieldView } from "@bitwarden/common/vault/models/view/field.view";
import { LoginUriView } from "@bitwarden/common/vault/models/view/login-uri.view";
import { CipherRepromptType } from "@bitwarden/common/vault/enums/cipher-reprompt-type";
import { FieldType } from "@bitwarden/common/vault/enums";
import { LoginSaveSchema, type LoginDetail, type LoginSave } from "./login-contracts";

/** Popup-owned Bitwarden view model; never handed to upstream account, SDK or storage services. */
export class LoginDraft {
  readonly cipher = new CipherView();
  folder = "";
  recoveryCodes = "";
  clearTotpSecret = false;
  clearRecoveryCodes = false;
  readonly hasTotpSecret: boolean;
  readonly hasRecoveryCodes: boolean;
  private disposed = false;

  constructor(detail?: LoginDetail) {
    this.hasTotpSecret = detail?.hasTotpSecret ?? false;
    this.hasRecoveryCodes = detail?.hasRecoveryCodes ?? false;
    const cipher = this.cipher;
    cipher.id = detail?.id;
    cipher.name = detail?.title ?? "";
    cipher.notes = detail?.notes ?? "";
    cipher.favorite = detail?.favorite ?? false;
    cipher.login.username = detail?.username ?? "";
    cipher.login.password = "";
    cipher.login.totp = "";
    cipher.login.autofillOnPageLoad = detail?.autofillOnPageLoad ?? true;
    cipher.reprompt = detail?.masterPasswordReprompt ? CipherRepromptType.Password : CipherRepromptType.None;
    cipher.login.uris = [detail?.url ?? "", ...(detail?.additionalUrls ?? [])].map((value) => {
      const uri = new LoginUriView();
      uri.uri = value;
      return uri;
    });
    cipher.fields = (detail?.customFields ?? []).map(({ label, value }) => {
      const field = new FieldView();
      field.name = label;
      field.value = value;
      field.type = FieldType.Hidden;
      return field;
    });
    this.folder = detail?.folder ?? "";
  }

  get reprompt(): boolean { return this.cipher.reprompt === CipherRepromptType.Password; }
  set reprompt(value: boolean) { this.cipher.reprompt = value ? CipherRepromptType.Password : CipherRepromptType.None; }

  addUri(): void {
    if (this.cipher.login.uris.length < 21) this.cipher.login.uris.push(new LoginUriView());
  }

  addField(): void {
    if ((this.cipher.fields?.length ?? 0) >= 50) return;
    const field = new FieldView();
    field.name = field.value = "";
    field.type = FieldType.Hidden;
    this.cipher.fields.push(field);
  }

  removeField(index: number): void {
    const field = this.cipher.fields[index];
    if (field) field.value = "";
    this.cipher.fields.splice(index, 1);
  }

  toInput(): LoginSave {
    if (this.disposed) throw new Error("expired-draft");
    const cipher = this.cipher;
    const codes = this.recoveryCodes.split(/\r?\n/).filter((code) => code.trim().length > 0);
    return LoginSaveSchema.parse({
      ...(cipher.id ? { id: cipher.id } : {}),
      title: cipher.name.trim(), username: cipher.login.username ?? "",
      password: cipher.login.password || null,
      url: cipher.login.uris[0]?.uri?.trim() || null,
      notes: cipher.notes || null, folder: this.folder.trim() || null,
      favorite: cipher.favorite,
      additionalUrls: cipher.login.uris.slice(1).map((uri) => uri.uri?.trim() ?? "").filter(Boolean),
      autofillOnPageLoad: cipher.login.autofillOnPageLoad ?? false,
      masterPasswordReprompt: this.reprompt,
      customFields: cipher.fields.map((field) => ({ label: field.name ?? "", value: field.value ?? "" })),
      totpSecret: cipher.login.totp || null,
      clearTotpSecret: this.clearTotpSecret,
      recoveryCodes: codes.length ? codes : cipher.id ? null : [],
      clearRecoveryCodes: this.clearRecoveryCodes,
    });
  }

  clear(): void {
    this.disposed = true;
    this.folder = this.recoveryCodes = "";
    this.cipher.name = this.cipher.notes = "";
    this.cipher.login.username = this.cipher.login.password = this.cipher.login.totp = "";
    for (const field of this.cipher.fields) field.name = field.value = "";
    this.cipher.fields = [];
    for (const uri of this.cipher.login.uris) uri.uri = "";
    this.cipher.login.uris = [];
  }
}
