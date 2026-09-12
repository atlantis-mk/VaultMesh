import { LoginDraft } from "./login-draft";
import { LoginDetailSchema, LoginSaveSchema, clearLoginSecrets } from "./login-contracts";

export const detail = {
  id: "00000000-0000-4000-8000-000000000005", title: "Example", username: "alice",
  url: null, notes: "note", folder: "Work", favorite: true,
  additionalUrls: ["https://example.test/login", "https://other.example.test"],
  hasTotpSecret: true, hasRecoveryCodes: true, autofillOnPageLoad: false,
  masterPasswordReprompt: true, customFields: [{ label: "account-id", value: "synthetic-custom-value" }],
};

describe("CT-ITEM-001 Bitwarden edit projection", () => {
  it("preserves every existing field and leaves unread secrets unchanged on a metadata-only edit", () => {
    const draft = new LoginDraft(detail);
    draft.cipher.name = "Renamed";
    expect(draft.toInput()).toEqual({
      id: detail.id, title: "Renamed", username: "alice", password: null, url: null,
      notes: "note", folder: "Work", favorite: true, additionalUrls: detail.additionalUrls,
      autofillOnPageLoad: false, masterPasswordReprompt: true, customFields: detail.customFields,
      totpSecret: null, recoveryCodes: null, clearTotpSecret: false, clearRecoveryCodes: false,
    });
    expect(draft.cipher.login.password).toBe("");
    expect(draft.cipher.login.totp).toBe("");
  });

  it("keeps the save payload independent from later draft cleanup", () => {
    const draft = new LoginDraft(detail);
    draft.cipher.login.password = "synthetic-new-password";
    draft.cipher.login.totp = "JBSWY3DPEHPK3PXP";
    draft.recoveryCodes = "code-one\ncode-two";
    const input = draft.toInput();
    draft.clear();
    expect(input.password).toBe("synthetic-new-password");
    expect(input.customFields[0].value).toBe("synthetic-custom-value");
    expect(input.recoveryCodes).toEqual(["code-one", "code-two"]);
    expect(JSON.stringify(draft)).not.toContain("synthetic-");
    expect(() => draft.toInput()).toThrow("expired-draft");
    clearLoginSecrets(input);
    expect(input.customFields[0].value).toBe("");
    expect(input.password).toBe("");
    expect(input.recoveryCodes).toEqual([]);
  });
  it("CT-RECOVERY-CODES-001 preserves imported whitespace and uses the core UTF-16 code limit", () => {
    const draft = new LoginDraft(detail);
    draft.recoveryCodes = " padded-code \n" + "码".repeat(256);
    expect(draft.toInput().recoveryCodes).toEqual([" padded-code ", "码".repeat(256)]);
    draft.recoveryCodes = "码".repeat(257);
    expect(() => draft.toInput()).toThrow();
  });

  it("requires a new password for creation and uses explicit removal flags only for existing secrets", () => {
    const draft = new LoginDraft();
    draft.cipher.name = "New";
    expect(() => draft.toInput()).toThrow();
    draft.cipher.login.password = "synthetic-password";
    const input = draft.toInput();
    expect(input.id).toBeUndefined();
    expect(input.recoveryCodes).toEqual([]);
    expect(LoginSaveSchema.safeParse({ ...input, clearTotpSecret: true }).success).toBe(false);
    const edit = new LoginDraft(detail);
    edit.clearTotpSecret = edit.clearRecoveryCodes = true;
    expect(edit.toInput()).toMatchObject({ clearTotpSecret: true, clearRecoveryCodes: true, totpSecret: null, recoveryCodes: null });
    edit.recoveryCodes = "replacement";
    expect(() => edit.toInput()).toThrow();
  });

  it("does not silently drop custom fields, and rejects overlong UTF-8 input or caller authorization", () => {
    const draft = new LoginDraft(detail);
    const input = draft.toInput();
    expect(LoginSaveSchema.safeParse({ ...input, customFields: Array(51).fill(detail.customFields[0]) }).success).toBe(false);
    expect(LoginSaveSchema.safeParse({ ...input, title: "密".repeat(100) }).success).toBe(false);
    expect(LoginSaveSchema.safeParse({ ...input, userGestureId: detail.id }).success).toBe(false);
    expect(LoginDetailSchema.parse({ ...detail, password: "not-allowed", totpSecret: "not-allowed" })).toEqual(detail);
  });

  it("clears removed custom-field objects even if a view still holds a reference", () => {
    const draft = new LoginDraft(detail);
    const field = draft.cipher.fields[0];
    draft.removeField(0);
    expect(field.value).toBe("");
    expect(draft.toInput().customFields).toEqual([]);
  });
});
