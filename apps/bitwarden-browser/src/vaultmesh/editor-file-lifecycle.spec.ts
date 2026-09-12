import { TestBed } from "@angular/core/testing";
import { BehaviorSubject } from "rxjs";
import { VaultMeshSessionComponent } from "./session.component";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";

const id = "11111111-1111-4111-8111-111111111111";
const result = () => ({ ok: true as const, value: { codes: ["synthetic-code", " padded-code "], fileName: "synthetic.txt",
  sourceFileStatus: "kept" as const, cleanup: { id, expiresAt: Date.now() + 300000 } } });

describe("CT-RECOVERY-CODES-001 bounded independent editor dialog lifecycle", () => {
  let component: VaultMeshSessionComponent;
  let states: BehaviorSubject<SessionState>;
  let service: { state$: unknown; start: jest.Mock; ngOnDestroy: jest.Mock; cancelFileDialog: jest.Mock;
    prepareRecoveryFile: jest.Mock; finishRecoveryFile: jest.Mock; saveLogin: jest.Mock; discardRecoveryFile: jest.Mock };
  beforeEach(() => {
    jest.useFakeTimers();
    states = new BehaviorSubject<SessionState>({ status: "ready", vault: null, logins: [], busy: false, error: null });
    service = { state$: states, start: jest.fn(), ngOnDestroy: jest.fn(), cancelFileDialog: jest.fn(),
      discardRecoveryFile: jest.fn(),
      prepareRecoveryFile: jest.fn().mockImplementation(async () => result()),
      finishRecoveryFile: jest.fn().mockResolvedValue({ ok: true, value: { sourceFileStatus: "kept" } }),
      saveLogin: jest.fn().mockResolvedValue({ ok: true, value: { id } }) };
    TestBed.configureTestingModule({ providers: [{ provide: VaultMeshBrowserRpcService, useValue: service }] });
    component = TestBed.runInInjectionContext(() => new VaultMeshSessionComponent());
    component.ngOnInit(); component["independentEditor"].set(true); component["newLogin"]();
    component["draft"]()!.cipher.name = "Synthetic";
    component["draft"]()!.cipher.login.password = "synthetic-password";
    jest.spyOn(document, "hidden", "get").mockReturnValue(false);
  });
  afterEach(() => { component.ngOnDestroy(); jest.restoreAllMocks(); jest.useRealTimers(); });

  it("preserves the same component draft only while its native file dialog is active", async () => {
    let complete!: (value: unknown) => void;
    service.prepareRecoveryFile.mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
    const draft = component["draft"]()!;
    const pending = component["importRecoveryFile"]();
    jest.spyOn(document, "hidden", "get").mockReturnValue(true);
    document.dispatchEvent(new Event("visibilitychange"));
    window.dispatchEvent(new Event("blur"));
    expect(component["draft"]()).toBe(draft); expect(draft.cipher.login.password).toBe("synthetic-password");
    const raw = result(); complete(raw);
    for (let tick = 0; tick < 8; tick++) await Promise.resolve();
    expect(component["fileDialogActive"]()).toBe(true);
    jest.spyOn(document, "hidden", "get").mockReturnValue(false);
    document.dispatchEvent(new Event("visibilitychange")); await pending;
    expect(raw.value.codes).toEqual([]);
    expect(draft.recoveryCodes).toBe("synthetic-code\n padded-code ");
    expect(draft.toInput().recoveryCodes).toEqual(["synthetic-code", " padded-code "]);
    expect(component["fileDialogActive"]()).toBe(false);
    jest.spyOn(document, "hidden", "get").mockReturnValue(true);
    document.dispatchEvent(new Event("visibilitychange"));
    expect(component["draft"]()).toBeNull(); expect(draft.recoveryCodes).toBe("");
  });

  it.each(["cancel", "lock", "close", "deadline", "original-expiry"])("clears immediately on %s and discards the late import", async (reason) => {
    let complete!: (value: unknown) => void;
    service.prepareRecoveryFile.mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
    if (reason === "original-expiry") jest.advanceTimersByTime(299000);
    const draft = component["draft"]()!;
    const pending = component["importRecoveryFile"]();
    if (reason === "cancel") component["closeEditor"]();
    if (reason === "lock") states.next({ ...states.value, status: "locked" });
    if (reason === "close") window.dispatchEvent(new Event("pagehide"));
    if (reason === "deadline") jest.advanceTimersByTime(45000);
    if (reason === "original-expiry") jest.advanceTimersByTime(1000);
    expect(component["draft"]()).toBeNull(); expect(draft.cipher.login.password).toBe("");
    const late = result(); complete(late); await pending;
    expect(late.value.codes).toEqual([]); expect(component["draft"]()).toBeNull();
    expect(service.finishRecoveryFile).not.toHaveBeenCalled();
  });

  it("offers cleanup only after unchanged imported codes have been saved, never during import", async () => {
    await component["importRecoveryFile"]();
    expect(service.finishRecoveryFile).not.toHaveBeenCalled();
    await component["saveLogin"]();
    expect(service.saveLogin).toHaveBeenCalledWith(expect.objectContaining({ recoveryCodes: ["synthetic-code", " padded-code "] }), id);
    expect(component["savedSource"]()?.cleanup.id).toBe(id);
    expect(service.finishRecoveryFile).not.toHaveBeenCalled();
    await component["finishSourceCleanup"]();
    expect(service.finishRecoveryFile).toHaveBeenCalledWith(id);
    await component["finishSourceCleanup"](); expect(service.finishRecoveryFile).toHaveBeenCalledTimes(1);
  });

  it.each(["edited", "save-failed"])("keeps the source when %s", async (reason) => {
    await component["importRecoveryFile"]();
    if (reason === "edited") component["draft"]()!.recoveryCodes = "changed-code";
    else service.saveLogin.mockResolvedValue({ ok: false, code: "execution-unknown" });
    await component["saveLogin"]();
    expect(component["savedSource"]()).toBeNull();
    expect(service.finishRecoveryFile).not.toHaveBeenCalled();
    if (reason === "edited") expect(service.saveLogin.mock.calls[0]).toHaveLength(1);
  });

  it("clears the draft when the native file picker is cancelled", async () => {
    service.prepareRecoveryFile.mockResolvedValue({ ok: false, code: "cancelled" });
    await component["importRecoveryFile"]();
    expect(component["draft"]()).toBeNull(); expect(service.finishRecoveryFile).not.toHaveBeenCalled();
  });
  it("does not retain an independent-window draft on ordinary focus loss", () => {
    const draft = component["draft"]()!;
    window.dispatchEvent(new Event("blur"));
    expect(component["draft"]()).toBeNull(); expect(draft.cipher.login.password).toBe("");
  });
});
