import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { BehaviorSubject } from "rxjs";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { VaultMeshI18nService } from "./i18n.service";
import { VaultMeshGeneratorComponent } from "./generator.component";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";
import { GeneratorPreferencesSchema, DEFAULT_GENERATOR_PREFERENCES, GENERATOR_KEY, loadGeneratorPreferences, saveGeneratorPreferences } from "./generator-preferences";
import { generateCredential } from "./credential-generator";
describe("CT-BROWSER-003 native generators and transient results", () => {
  let stored: Record<string, unknown>;
  beforeEach(() => {
    stored = {};
    jest.spyOn(chrome.storage.local, "get").mockImplementation((_key: any, callback: any) => callback(stored));
    jest.spyOn(chrome.storage.local, "set").mockImplementation((value: any, callback: any) => { stored = value; callback(); });
  });
  afterEach(() => { TestBed.resetTestingModule(); jest.restoreAllMocks(); jest.useRealTimers(); });
  it.each(["password", "passphrase", "username", "uuid"] as const)("generates %s without persisting results", async (mode) => {
    const preferences = GeneratorPreferencesSchema.parse({ ...DEFAULT_GENERATOR_PREFERENCES, mode });
    const result = await generateCredential(preferences); expect(result.length).toBeGreaterThan(0);
    if (mode === "password") expect(result).toHaveLength(20);
    if (mode === "passphrase") expect(result.split("-")).toHaveLength(5);
    if (mode === "username") { expect(result).toHaveLength(16); expect(result).toMatch(/^vm_.*\d{2}$/); }
    if (mode === "uuid") expect(result).toMatch(/^[a-f0-9-]{36}$/);
    expect(stored).toEqual({});
    expect(await saveGeneratorPreferences(preferences)).toBe(true);
    expect(stored).toEqual({ [GENERATOR_KEY]: preferences }); expect(JSON.stringify(stored)).not.toContain(result);
    expect(await loadGeneratorPreferences()).toEqual(preferences);
  });
  it("applies exact character minima and rejects impossible/empty rules", async () => {
    const preferences = GeneratorPreferencesSchema.parse(DEFAULT_GENERATOR_PREFERENCES);
    preferences.password = { ...preferences.password, length: 8, uppercase: false, symbols: false, minimumNumbers: 5 };
    const result = await generateCredential(preferences); expect(result).toHaveLength(8); expect(result).toMatch(/^[a-z0-9]+$/);
    expect(result.replace(/\D/g, "").length).toBeGreaterThanOrEqual(5);
    preferences.password.length = 7; expect(await saveGeneratorPreferences(preferences)).toBe(false);
    expect(GeneratorPreferencesSchema.safeParse({ ...DEFAULT_GENERATOR_PREFERENCES, secret: "forbidden" }).success).toBe(false);
  });
  it("uses safe defaults for corrupt storage and a failed storage API", async () => {
    stored = { [GENERATOR_KEY]: { mode: "cloud" } }; expect(await loadGeneratorPreferences()).toEqual(DEFAULT_GENERATOR_PREFERENCES);
    jest.mocked(chrome.storage.local.get).mockImplementation(() => { throw new Error("unavailable"); });
    expect(await loadGeneratorPreferences()).toEqual(DEFAULT_GENERATOR_PREFERENCES);
  });
  it("renders a generated result then clears it on deadline and lock without storage writes of the result", async () => {
    const state$ = new BehaviorSubject({ status: "ready", sessionId: "s", revision: 0 });
    await TestBed.configureTestingModule({ imports: [VaultMeshGeneratorComponent], providers: [provideNoopAnimations(),
      { provide: VaultMeshBrowserRpcService, useValue: { state$ } }, { provide: I18nService, useClass: VaultMeshI18nService }] }).compileComponents();
    const fixture = TestBed.createComponent(VaultMeshGeneratorComponent); fixture.detectChanges(); await fixture.whenStable();
    jest.useFakeTimers(); await fixture.componentInstance["generate"](); fixture.detectChanges();
    const result = fixture.componentInstance["value"](); expect(result).toHaveLength(20);
    expect(fixture.nativeElement.querySelector('input[readonly]').value).toBe(result);
    const colored = fixture.nativeElement.querySelector('bit-color-password');
    const copy = new Event('copy', { bubbles: true, cancelable: true });
    colored.dispatchEvent(copy);
    expect(copy.defaultPrevented).toBe(true);
    expect(JSON.stringify(stored)).not.toContain(result);
    jest.advanceTimersByTime(60001); expect(fixture.componentInstance["value"]()).toBe("");
    await fixture.componentInstance["generate"](); state$.next({ ...state$.value, status: "locked" }); expect(fixture.componentInstance["value"]()).toBe(""); fixture.destroy();
  });
});
