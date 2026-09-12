import { TestBed, type ComponentFixture } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { BehaviorSubject } from "rxjs";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { VaultMeshI18nService } from "./i18n.service";
import { VaultMeshUnlockComponent } from "./unlock.component";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";

describe("CT-SEC-002 available-only unlock page", () => {
  let fixture: ComponentFixture<VaultMeshUnlockComponent>;
  let states: BehaviorSubject<SessionState>;
  let pin: { enabled: boolean; locked: boolean; remainingAttempts: number; failureLimit: number; failedAttempts: number };
  let biometric: { available: boolean; enabled: boolean; kind: "touchId" | null };
  let service: { state$: unknown; securityTool: jest.Mock; unlock: jest.Mock; readUnlockMethods: jest.Mock };
  const settle = async () => { fixture.detectChanges(); await fixture.whenStable(); fixture.detectChanges(); };
  const component = () => fixture.componentInstance;
  const text = () => fixture.nativeElement.textContent as string;

  beforeEach(async () => {
    states = new BehaviorSubject<SessionState>({ status: "locked", vault: { hasVault: true, unlocked: false, itemCount: 0 }, logins: [], busy: false, error: null });
    pin = { enabled: false, locked: false, remainingAttempts: 5, failureLimit: 5, failedAttempts: 0 };
    biometric = { available: false, enabled: false, kind: null };
    service = { state$: states.asObservable(), readUnlockMethods: jest.fn(() => Promise.all(["pin.status", "biometric.status"].map(operation => service.securityTool({ operation, input: {} })))), unlock: jest.fn().mockResolvedValue(undefined), securityTool: jest.fn(async command => {
      if (command.operation === "pin.status") return { ok: true, value: { ...pin } };
      if (command.operation === "biometric.status") return { ok: true, value: { ...biometric } };
      return { ok: false, code: "operation-failed" };
    }) };
    await TestBed.configureTestingModule({ imports: [VaultMeshUnlockComponent], providers: [provideNoopAnimations(),
      { provide: VaultMeshBrowserRpcService, useValue: service }, { provide: I18nService, useClass: VaultMeshI18nService }] }).compileComponents();
    fixture = TestBed.createComponent(VaultMeshUnlockComponent);
  });
  afterEach(() => { fixture.destroy(); TestBed.resetTestingModule(); });

  it.each([
    [false, false, false, false, "password"],
    [true, false, false, false, "pin"],
    [false, false, true, true, "biometric"],
    [true, false, true, true, "pin"],
    [true, true, false, false, "password"],
    [true, true, true, true, "biometric"],
    [false, false, true, false, "password"],
    [false, false, false, true, "password"],
  ] as const)("PIN %s locked %s / biometric available %s enabled %s defaults to %s", async (pinEnabled, locked, available, enabled, method) => {
    pin.enabled = pinEnabled; pin.locked = locked;
    biometric.available = available; biometric.enabled = enabled;
    await settle();
    expect(component()["method"]()).toBe(method);
    expect(!!fixture.nativeElement.querySelector('[name="masterPassword"]')).toBe(method === "password");
    expect(!!fixture.nativeElement.querySelector('[name="pluginUnlockPin"]')).toBe(method === "pin");
    expect([...fixture.nativeElement.querySelectorAll('button')].some((button: any) => button.textContent.includes("指纹"))).toBe(available && enabled);
    expect(service.securityTool.mock.calls.map(([command]) => command.operation)).toEqual(["pin.status", "biometric.status"]);
    expect(service.unlock).not.toHaveBeenCalled();
  });

  it("keeps unknown methods hidden during initialization and falls back after a read failure", async () => {
    service.securityTool.mockResolvedValue({ ok: false, code: "operation-failed" });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[name="pluginUnlockPin"]')).toBeNull();
    await settle();
    expect(component()["method"]()).toBe("password");
    expect(text()).not.toContain("改用 PIN"); expect(text()).not.toContain("改用指纹");
  });

  it("clears the credential when switching and submits master password only on request", async () => {
    pin.enabled = true; biometric.available = biometric.enabled = true;
    await settle();
    component()["inputCredential"]("12"); component()["choose"]("password"); await settle();
    expect(component()["credential"]()).toBe("");
    component()["inputCredential"]("synthetic-password");
    service.unlock.mockImplementation(async () => { expect(component()["credential"]()).toBe(""); });
    await component()["unlock"]();
    expect(service.unlock).toHaveBeenCalledWith("synthetic-password");
    component()["choose"]("pin");
    expect(component()["credential"]()).toBe("");
  });

  it("submits a complete PIN once, clears it before dispatch and rereads attempts after rejection", async () => {
    pin.enabled = true; await settle();
    let reply!: (value: unknown) => void;
    service.securityTool.mockImplementation(command => {
      if (command.operation === "pin.unlock") {
        expect(component()["credential"]()).toBe("");
        expect(command.input.pin).toBe("123456");
        return new Promise(resolve => { reply = resolve; });
      }
      return Promise.resolve({ ok: true, value: command.operation === "pin.status" ? { ...pin } : { ...biometric } });
    });
    component()["inputCredential"]("12345"); expect(service.securityTool).toHaveBeenCalledTimes(2);
    component()["inputCredential"]("123456"); component()["inputCredential"]("123456");
    await component()["unlock"]();
    expect(service.securityTool.mock.calls.filter(([command]) => command.operation === "pin.unlock")).toHaveLength(1);
    pin.locked = true; pin.remainingAttempts = 0;
    reply({ ok: false, code: "operation-failed" }); await settle();
    expect(component()["method"]()).toBe("password");
    expect(text()).not.toContain("改用 PIN");
    expect(service.securityTool.mock.calls.find(([command]) => command.operation === "pin.unlock")![0].input.pin).toBe("");
  });

  it("does not trigger biometrics until clicked and allows password fallback after cancellation", async () => {
    biometric.available = biometric.enabled = true; await settle();
    expect(service.securityTool).toHaveBeenCalledTimes(2);
    await component()["unlock"](); await settle();
    expect(service.securityTool.mock.calls.filter(([command]) => command.operation === "biometric.unlock")).toHaveLength(1);
    expect(text()).toContain("系统验证未完成或已取消");
    component()["choose"]("password"); await settle();
    expect(fixture.nativeElement.querySelector('[name="masterPassword"]')).not.toBeNull();
  });

  it("discards a late status reply after leaving the popup", async () => {
    let reply!: (value: unknown) => void;
    service.readUnlockMethods.mockImplementation(() => new Promise(resolve => { reply = resolve; }));
    fixture.detectChanges();
    window.dispatchEvent(new Event("pagehide"));
    reply([{ ok: true, value: { ...pin, enabled: true } }, { ok: true, value: biometric }]); await settle();
    expect(component()["pin"]()).toBeNull();
    expect(service.readUnlockMethods).toHaveBeenCalledTimes(1);
  });

  it("clears entered input on page hide and independent window blur", async () => {
    await settle(); component().independent = true;
    component()["inputCredential"]("synthetic-password"); window.dispatchEvent(new Event("blur"));
    expect(component()["credential"]()).toBe("");
    component()["inputCredential"]("synthetic-password"); window.dispatchEvent(new Event("pagehide"));
    expect(component()["credential"]()).toBe("");
    states.next({ ...states.value, status: "unavailable" });
    expect(component()["pin"]()).toBeNull();
  });
});
