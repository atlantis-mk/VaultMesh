import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { BehaviorSubject } from "rxjs";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { VaultMeshI18nService } from "./i18n.service";
import { VaultMeshSessionComponent } from "./session.component";
import { VaultMeshVaultLifecycleComponent } from "./vault-lifecycle.component";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";
import { collectQr } from "./qr-popup";
import { parseTotpQr } from "./qr-contracts";
jest.mock("./qr-popup", () => ({ collectQr: jest.fn() }));
const id = "00000000-0000-4000-8000-000000000031";
const uri = "otpauth://totp/Synthetic:user?secret=JBSWY3DPEHPK3PXP";
describe("CT-AUTHENTICATOR-001 / CT-EMAIL-003 / CT-VAULT-001/002 actual popup surfaces", () => {
  const state$ = new BehaviorSubject<SessionState>({ status: "ready", logins: [], busy: false, error: null });
  const service = { state$, start: jest.fn(), ngOnDestroy: jest.fn(), authorizeQr: jest.fn(), emailCandidates: jest.fn(), fillEmail: jest.fn(), securityTool: jest.fn(), cancelManaged: jest.fn(), saveLogin: jest.fn() };
  beforeEach(() => { jest.clearAllMocks(); state$.next({ status: "ready", logins: [], busy: false, error: null }); });
  afterEach(() => { TestBed.resetTestingModule(); jest.useRealTimers(); jest.restoreAllMocks(); });
  async function root() {
    await TestBed.configureTestingModule({ imports: [VaultMeshSessionComponent], providers: [provideNoopAnimations(), { provide: I18nService, useClass: VaultMeshI18nService }] })
      .overrideComponent(VaultMeshSessionComponent, { set: { providers: [{ provide: VaultMeshBrowserRpcService, useValue: service }] } }).compileComponents();
    const fixture = TestBed.createComponent(VaultMeshSessionComponent); fixture.detectChanges(); return fixture;
  }
  it("scans into a draft only after explicit choice and overwrite confirmation, preserving the original draft deadline", async () => {
    service.authorizeQr.mockResolvedValue({ ok: true, value: {} }); jest.mocked(collectQr).mockResolvedValue([parseTotpQr(uri)!]);
    const fixture = await root(); jest.useFakeTimers(); const component = fixture.componentInstance;
    component["newLogin"](); const draft = component["draft"]()!; draft.cipher.login.totp = "existing-synthetic-seed";
    const deadline = component["editorDeadline"]; await component["scanQr"](); fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain("二维码候选"); component["applyQr"](0);
    expect(draft.cipher.login.totp).toBe("existing-synthetic-seed"); component["qrOverwrite"] = true; component["applyQr"](0);
    expect(draft.cipher.login.totp).toBe(uri); expect(component["qrCandidates"]()).toEqual([]);
    expect(component["editorDeadline"]).toBe(deadline); expect(service.saveLogin).not.toHaveBeenCalled();
    state$.next({ ...state$.value, status: "locked" }); expect(draft.cipher.login.totp).toBe(""); fixture.destroy();
  });
  it("shows bounded global mail candidates then clears them on top-frame navigation without filling", async () => {
    const value = { tabId: 2, url: "https://site.test/", candidates: [{ id, code: "A1b2", sourceDomain: "different.test", receivedAt: 1, expiresAt: Math.floor(Date.now() / 1000) + 60 }] };
    service.emailCandidates.mockResolvedValue({ ok: true, value }); const fixture = await root();
    await fixture.componentInstance["openEmail"](); fixture.detectChanges(); expect(fixture.nativeElement.textContent).toContain("A1b2");
    fixture.componentInstance["pageNavigated"]({ tabId: 2, frameId: 0 }); fixture.detectChanges();
    expect(value.candidates[0].code).toBe(""); expect(fixture.nativeElement.textContent).not.toContain("A1b2"); expect(service.fillEmail).not.toHaveBeenCalled(); fixture.destroy();
  });
  it("requires matching passwords and confirmation, clears password inputs before dispatch and on expiry", async () => {
    await TestBed.configureTestingModule({ imports: [VaultMeshVaultLifecycleComponent], providers: [provideNoopAnimations(),
      { provide: I18nService, useClass: VaultMeshI18nService }, { provide: VaultMeshBrowserRpcService, useValue: service }] }).compileComponents();
    const fixture = TestBed.createComponent(VaultMeshVaultLifecycleComponent); fixture.componentRef.setInput("hasVault", false); fixture.detectChanges(); jest.useFakeTimers();
    const component = fixture.componentInstance; component["password"] = "synthetic-master"; component["repeat"] = "wrong"; component["confirmed"] = true; component["changed"]();
    await component["save"](); expect(service.securityTool).not.toHaveBeenCalled();
    component["repeat"] = component["password"];
    service.securityTool.mockImplementation(async () => { expect(component["password"]).toBe(""); expect(component["repeat"]).toBe(""); return { ok: true, value: {} }; });
    await component["save"](); expect(service.securityTool).toHaveBeenCalledWith({ operation: "vault.create", input: { masterPassword: "synthetic-master" }, confirmed: true });
    component["password"] = "another-synthetic"; component["changed"](); jest.advanceTimersByTime(300001); expect(component["password"]).toBe(""); fixture.destroy();
  });
});
