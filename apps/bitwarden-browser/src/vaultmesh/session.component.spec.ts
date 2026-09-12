import { TestBed } from "@angular/core/testing";
import { BehaviorSubject } from "rxjs";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";
import { VaultMeshSessionComponent } from "./session.component";
import { type LoginDetail } from "./login-contracts";
import { type LoginDraft } from "./login-draft";

const id = "00000000-0000-4000-8000-000000000005";
const detail = (): LoginDetail => ({ id, title: "Example", username: "alice", url: null,
  notes: null, folder: null, favorite: false, additionalUrls: [], hasTotpSecret: true,
  hasRecoveryCodes: true, autofillOnPageLoad: false, masterPasswordReprompt: false,
  customFields: [{ label: "key", value: "synthetic-field-secret" }] });

describe("CT-ITEM-001 popup edit lifecycle", () => {
  let component: VaultMeshSessionComponent;
  let states: BehaviorSubject<SessionState>;
  let service: { state$: unknown; start: jest.Mock; ngOnDestroy: jest.Mock; editLogin: jest.Mock; saveLogin: jest.Mock; deleteLogin: jest.Mock; fillLogin: jest.Mock; fillContexts: jest.Mock; recoveryCodes: jest.Mock; copyRecoveryCode: jest.Mock };
  beforeEach(() => {
    states = new BehaviorSubject<SessionState>({ status: "ready", vault: { unlocked: true, hasVault: true, itemCount: 1 }, logins: [], busy: false, error: null });
    service = { state$: states.asObservable(), start: jest.fn(), ngOnDestroy: jest.fn(),
      editLogin: jest.fn().mockImplementation(async () => ({ ok: true, value: detail() })),
      saveLogin: jest.fn().mockResolvedValue({ ok: true }), deleteLogin: jest.fn().mockResolvedValue({ ok: true }),
      fillLogin: jest.fn().mockResolvedValue({ ok: true, value: { filled: 2, auditRecorded: true } }),
      fillContexts: jest.fn().mockResolvedValue({ ok: true, value: [] }),
      recoveryCodes: jest.fn().mockImplementation(async () => ({ ok: true, value: { codes: ["synthetic-recovery"] } })),
      copyRecoveryCode: jest.fn().mockResolvedValue({ ok: true, value: { clearsAt: Date.now() + 30000 } }) };
    TestBed.configureTestingModule({ providers: [{ provide: VaultMeshBrowserRpcService, useValue: service }] });
    component = TestBed.runInInjectionContext(() => new VaultMeshSessionComponent());
    component.ngOnInit();
  });
  afterEach(() => { component.ngOnDestroy(); jest.useRealTimers(); });

  it("CT-BROWSER-001 bounds large-vault projection while searching the entire summary list", () => {
    const logins = Array.from({ length: 521 }, (_, index) => ({ id: `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`, title: `Synthetic ${index}`, username: "synthetic", url: null, hasPassword: true, hasTotpSecret: false, hasRecoveryCodes: false, autofillOnPageLoad: false, masterPasswordReprompt: false }));
    states.next({ ...states.value, logins });
    expect(component["rows"]()).toHaveLength(25);
    component["setLoginQuery"]("Synthetic 520");
    expect(component["rows"]().map(row => row.name)).toEqual(["Synthetic 520"]);
    component["setLoginQuery"]("");
    component["changeLoginPage"](1);
    expect(component["rows"]()[0].id).toBe(logins[25].id);
    for (let page = 0; page < 30; page++) component["changeLoginPage"](1);
    expect(component["rows"]()).toHaveLength(21);
    expect(component["rows"]().at(-1)?.id).toBe(logins[520].id);
    states.next({ ...states.value, logins: logins.slice(0, 2) });
    expect(component["rows"]()).toHaveLength(2);
    states.next({ ...states.value, status: "locked", logins: [] });
    expect(component["rows"]()).toEqual([]);
    expect(component["loginPage"]()).toBe(0);
  });

  it("CT-BROWSER-001 opens summary-only view and clears it when authorization is lost", () => {
    states.next({ ...states.value, logins: [{ id, title: "Example", username: "alice", url: null,
      hasPassword: true, hasTotpSecret: false, hasRecoveryCodes: false,
      autofillOnPageLoad: false, masterPasswordReprompt: false }] });
    component["viewLogin"](id);
    expect(component["viewedLogin"]()?.title).toBe("Example");
    expect(service.editLogin).not.toHaveBeenCalled();
    expect(component["hasDetail"]()).toBe(true);
    states.next({ ...states.value, status: "locked", logins: [] });
    expect(component["viewedLoginId"]()).toBeNull();
    expect(component["viewedLogin"]()).toBeNull();
  });

  it("CT-AUTOFILL-001 fills a selected login directly and keeps reprompt behind confirmation", async () => {
    states.next({ ...states.value, logins: [{ id, title: "Example", username: "alice", url: null,
      hasPassword: true, hasTotpSecret: false, hasRecoveryCodes: false,
      autofillOnPageLoad: false, masterPasswordReprompt: false }] });
    await component["selectLogin"](id);
    expect(service.fillLogin).toHaveBeenCalledWith(id);
    expect(component["notice"]()).toContain("已填入 2 个字段");

    service.fillLogin.mockClear();
    states.next({ ...states.value, logins: [{ ...states.value.logins[0], masterPasswordReprompt: true }] });
    await component["selectLogin"](id);
    expect(service.fillLogin).not.toHaveBeenCalled();
    expect(component["fillTarget"]()?.id).toBe(id);
  });

  it("CT-AUTOFILL-001 requires explicit fill confirmation and clears reprompt input before waiting", async () => {
    states.next({ ...states.value, logins: [{ id, title: "Example", username: "alice", url: null, hasPassword: true,
      hasTotpSecret: false, hasRecoveryCodes: false, masterPasswordReprompt: true, autofillOnPageLoad: false }] });
    component["requestFill"](id);
    expect(service.fillLogin).not.toHaveBeenCalled();
    component["fillPassword"] = "synthetic-reprompt";
    service.fillLogin.mockImplementationOnce(async (_id, password) => {
      expect(component["fillPassword"]).toBe(""); expect(component["fillTarget"]()).toBeNull();
      expect(password).toBe("synthetic-reprompt");
      return { ok: true, value: { filled: 2, auditRecorded: true } };
    });
    await component["confirmFill"]();
    expect(component["notice"]()).toContain("已填入 2 个字段，未提交表单");
    await component["confirmFill"]();
    expect(service.fillLogin).toHaveBeenCalledTimes(1);
  });

  it.each(["close", "lock", "pagehide", "expiry"])("CT-RECOVERY-CODES-001 clears displayed recovery codes on %s", async (reason) => {
    jest.useFakeTimers();
    states.next({ ...states.value, logins: [{ id, title: "Example", username: "alice", url: null, hasPassword: true,
      hasTotpSecret: false, hasRecoveryCodes: true, masterPasswordReprompt: false, autofillOnPageLoad: false }] });
    component["requestCodes"](id);
    await component["confirmCodes"]();
    expect(service.recoveryCodes).not.toHaveBeenCalled();
    component["fillPassword"] = "synthetic-master-password";
    await component["confirmCodes"]();
    expect(service.recoveryCodes).toHaveBeenCalledWith(id, "synthetic-master-password");
    expect(component["fillPassword"]).toBe("");
    const view = component["codesView"]()!;
    expect(view.codes).toEqual(["synthetic-recovery"]);
    if (reason === "close") component["closeEditor"]();
    if (reason === "lock") states.next({ ...states.value, status: "locked" });
    if (reason === "pagehide") window.dispatchEvent(new Event("pagehide"));
    if (reason === "expiry") jest.advanceTimersByTime(30000);
    expect(component["codesView"]()).toBeNull(); expect(view.codes).toEqual([]);
  });

  it("CT-RECOVERY-CODES-001 asks for a new password before copying a viewed code", async () => {
    states.next({ ...states.value, logins: [{ id, title: "Example", username: "alice", url: null, hasPassword: true,
      hasTotpSecret: false, hasRecoveryCodes: true, masterPasswordReprompt: false, autofillOnPageLoad: false }] });
    component["requestCodes"](id); component["fillPassword"] = "synthetic-master-password";
    await component["confirmCodes"]();
    component["requestCodes"](id, 0);
    expect(component["codesView"]()).toBeNull();
    await component["confirmCodes"](); expect(service.copyRecoveryCode).not.toHaveBeenCalled();
    component["fillPassword"] = "synthetic-new-verification";
    await component["confirmCodes"]();
    expect(service.copyRecoveryCode).toHaveBeenCalledWith(id, 0, "synthetic-new-verification");
  });

  it.each(["cancel", "lock", "pagehide", "destroy", "expiry"])("clears held field references after %s", async (reason) => {
    jest.useFakeTimers();
    await component["editLogin"](id);
    const draft = component["draft"]() as LoginDraft;
    const field = draft.cipher.fields[0];
    draft.cipher.login.password = "synthetic-password";
    if (reason === "cancel") component["closeEditor"]();
    if (reason === "lock") states.next({ ...states.value, status: "locked", vault: null });
    if (reason === "pagehide") window.dispatchEvent(new Event("pagehide"));
    if (reason === "destroy") component.ngOnDestroy();
    if (reason === "expiry") jest.advanceTimersByTime(5 * 60_000);
    expect(component["draft"]()).toBeNull();
    expect(field.value).toBe("");
    expect(draft.cipher.login.password).toBe("");
  });

  it("discards detail delivered after the user closes its editor", async () => {
    let complete!: (value: unknown) => void;
    service.editLogin.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
    const pending = component["editLogin"](id);
    component["closeEditor"]();
    const late = detail();
    complete({ ok: true, value: late });
    await pending;
    expect(component["draft"]()).toBeNull();
    expect(late.customFields[0].value).toBe("");
  });

  it("clears an editor after a broker event even when both status samples are ready", async () => {
    states.next({ ...states.value, revision: 0 });
    await component["editLogin"](id);
    const draft = component["draft"]()!;
    states.next({ ...states.value, revision: 1 });
    expect(component["draft"]()).toBeNull();
    expect(draft.cipher.fields).toEqual([]);
  });

  it("requires a separate confirm action to delete and supports cancellation", async () => {
    await component["editLogin"](id);
    component["requestDelete"]();
    expect(service.deleteLogin).not.toHaveBeenCalled();
    expect(component["draft"]()).toBeNull();
    component["closeEditor"]();
    await component["confirmDelete"]();
    expect(service.deleteLogin).not.toHaveBeenCalled();
    await component["editLogin"](id);
    component["requestDelete"]();
    await component["confirmDelete"]();
    expect(service.deleteLogin).toHaveBeenCalledTimes(1);
    expect(service.deleteLogin).toHaveBeenCalledWith(id);
  });

  it("rechecks expiration at submission even if the timer has not run", async () => {
    await component["editLogin"](id);
    const now = jest.spyOn(Date, "now").mockReturnValue(Date.now() + 6 * 60_000);
    await component["saveLogin"]();
    now.mockRestore();
    expect(service.saveLogin).not.toHaveBeenCalled();
    expect(component["draft"]()).toBeNull();
  });

  it("clears the draft before awaiting save and does not report success for an unknown result", async () => {
    await component["editLogin"](id);
    const draft = component["draft"]()!;
    service.saveLogin.mockImplementationOnce(async (input) => {
      expect(draft.cipher.fields).toEqual([]);
      expect(component["draft"]()).toBeNull();
      expect(input.customFields[0].value).toBe("synthetic-field-secret");
      return { ok: false, code: "execution-unknown" };
    });
    await component["saveLogin"]();
    expect(component["notice"]()).toContain("尚未确认操作结果");
  });
});
