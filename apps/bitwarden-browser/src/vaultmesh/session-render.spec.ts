import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { BehaviorSubject } from "rxjs";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { VaultMeshI18nService } from "./i18n.service";
import { VaultMeshSessionComponent } from "./session.component";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";

describe("CT-BROWSER-001 isolated popup rendering", () => {
  it("renders the real native form controls without AppModule/account/SDK services", async () => {
    const state$ = new BehaviorSubject<SessionState>({ status: "ready", logins: [], busy: false, error: null });
    const service = { state$, start: jest.fn(), ngOnDestroy: jest.fn() };
    await TestBed.configureTestingModule({ imports: [VaultMeshSessionComponent], providers: [
      provideNoopAnimations(), { provide: I18nService, useClass: VaultMeshI18nService },
    ] }).overrideComponent(VaultMeshSessionComponent, { set: { providers: [{ provide: VaultMeshBrowserRpcService, useValue: service }] } }).compileComponents();
    const fixture = TestBed.createComponent(VaultMeshSessionComponent);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain("保险库暂无登录信息");
    fixture.componentInstance["newLogin"](); fixture.detectChanges();
    expect(fixture.nativeElement.querySelector("vaultmesh-login-editor input")).not.toBeNull();
    fixture.componentInstance["closeEditor"]();
    state$.next({ ...state$.value, status: "locked", vault: { hasVault: true, unlocked: false, itemCount: 0 } });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('input[name="masterPassword"]')).not.toBeNull();
    fixture.destroy();
  });
  it("CT-RECOVERY-001 renders recovery actions, requires confirmation and clears them on lock", async () => {
    const itemId = "33333333-3333-4333-8333-333333333333";
    const trashId = "44444444-4444-4444-8444-444444444444";
    const state$ = new BehaviorSubject<SessionState>({ status: "ready", vault: null, logins: [], busy: false, error: null });
    const service = { state$, start: jest.fn(), ngOnDestroy: jest.fn(), loginTrash: jest.fn().mockResolvedValue({ ok: true, value: [
      { itemId, trashId, title: "Synthetic deleted login", username: "user", deletedAt: 1 },
    ] }), recoverLogin: jest.fn().mockResolvedValue({ ok: true, value: null }) };
    await TestBed.configureTestingModule({ imports: [VaultMeshSessionComponent], providers: [
      provideNoopAnimations(), { provide: I18nService, useClass: VaultMeshI18nService },
    ] }).overrideComponent(VaultMeshSessionComponent, { set: { providers: [{ provide: VaultMeshBrowserRpcService, useValue: service }] } }).compileComponents();
    const fixture = TestBed.createComponent(VaultMeshSessionComponent);
    fixture.detectChanges();
    await fixture.componentInstance["openRecovery"](); fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain("Synthetic deleted login");
    const buttons = Array.from(fixture.nativeElement.querySelectorAll("button")) as HTMLButtonElement[];
    buttons.find((button) => button.textContent?.trim() === "永久删除")!.click(); fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[role="alertdialog"]')?.textContent).toContain("此操作不能撤销");
    expect(service.recoverLogin).not.toHaveBeenCalled();
    state$.next({ ...state$.value, status: "locked" }); fixture.detectChanges();
    await fixture.componentInstance["confirmRecovery"]();
    expect(service.recoverLogin).not.toHaveBeenCalled();
    expect(fixture.componentInstance["recoveryTarget"]()).toBeNull();
    expect(fixture.componentInstance["recovery"]()).toBeNull();
    fixture.destroy();
  });
});
