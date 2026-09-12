import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { VaultMeshI18nService } from "./i18n.service";
import { VaultMeshSecurityToolsComponent } from "./security-tools.component";
import { VaultMeshRpcBackground } from "../background/vaultmesh-rpc.background";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";
import { VaultMeshRpcClient } from "./rpc";
import { SECURITY_TOOLS, SecurityCommandSchema, type SecurityCommand } from "./security-tools";
import { DEFAULT_SECURITY_SETTINGS } from "./vendor/model-contracts";
import { sendSessionMessage } from "./runtime";
import { type NativeRpcRequest } from "./native-connection";
import { DEFAULT_PLUGIN_POLICY, PLUGIN_POLICY_KEY, loadPluginPolicy, savePluginPolicy } from "./plugin-security";
import { SESSION_MESSAGE, SessionMessageSchema } from "./contracts";
jest.mock("./runtime", () => ({ sendSessionMessage: jest.fn(), requestNativePermission: jest.fn() }));
const token = "00000000-0000-4000-8000-000000000026";
const pin = { enabled: true, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 };
const biometric = { available: true, enabled: true, kind: "touchId" };
const success = (request: NativeRpcRequest, result: unknown) => ({ kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true, result });
describe("CT-BROWSER-001 desktop-only workflow scope", () => {
  it.each(["vault.backup", "vault.restore", "imports.select", "imports.commit", "imports.cancel", "ssh.scan", "ssh.scan.commit", "ssh.scan.cancel"])("does not expose %s as a fork session/tool operation", (operation) => {
    const command = { operation, input: {}, confirmed: true };
    const identity = { mutationId: token, sessionId: token, revision: 0, expiresAt: new Date(Date.now() + 30000).toISOString() };
    expect(SecurityCommandSchema.safeParse(command).success).toBe(false);
    expect(SessionMessageSchema.safeParse({ kind: SESSION_MESSAGE, action: "security-tool", command, ...identity }).success).toBe(false);
    expect(SessionMessageSchema.safeParse({ kind: SESSION_MESSAGE, action: operation, ...identity }).success).toBe(false);
  });
});
describe("CT-SEC-002 / CT-BROWSER-003 real security adapter chain", () => {
  let service: VaultMeshBrowserRpcService;
  let bridge: VaultMeshRpcBackground;
  let state: SessionState;
  let requests: NativeRpcRequest[];
  let unlocked: boolean;
  let reply: (request: NativeRpcRequest) => Promise<unknown>;
  beforeEach(async () => {
    jest.clearAllMocks(); requests = []; unlocked = true;
    reply = async (request) => {
      const operation = request.operation;
      if (operation === "events.poll") return success(request, { sequence: 0, events: [] });
      if (operation === "vault.status") return success(request, { unlocked, hasVault: true, itemCount: 0 });
      if (operation === "items.list") return success(request, []);
      if (operation === "confirmation.request") return success(request, { confirmationToken: token, expiresAt: new Date(Date.now() + 30000).toISOString() });
      if (operation.endsWith(".unlock")) { unlocked = true; return success(request, { cancelled: false, status: { unlocked, hasVault: true, itemCount: 0 } }); }
      if (operation.startsWith("pin.")) return success(request, pin);
      if (operation.startsWith("biometric.")) return success(request, biometric);
      if (operation.startsWith("security.settings.")) return success(request, operation.endsWith("update") ? { ...DEFAULT_SECURITY_SETTINGS, ...request.input, userGestureId: undefined } : DEFAULT_SECURITY_SETTINGS);
      if (operation.startsWith("browser.pairing.")) return success(request, { paired: !operation.endsWith("revoke") });
      if (operation === "password.health") return success(request, { score: 90, weakItemIds: [], reusedItemIds: [], oldItemIds: [] });
      return success(request, []);
    };
    const client = new VaultMeshRpcClient({ start: jest.fn(), dispose: jest.fn(), onDisconnected: jest.fn(),
      request: async (request: NativeRpcRequest) => { requests.push(JSON.parse(JSON.stringify(request))); return reply(request); } } as never);
    bridge = new VaultMeshRpcBackground(client); bridge.start();
    jest.mocked(sendSessionMessage).mockImplementation((message) => bridge.handle(message));
    service = new VaultMeshBrowserRpcService(); service.state$.subscribe((value) => state = value); await service.refresh();
  });
  afterEach(() => { service.ngOnDestroy(); TestBed.resetTestingModule(); });
  it("CT-VAULT-001 creates only an absent Vault with a fresh confirmation and clears its master password", async () => {
    let created = false; const previous = reply;
    reply = async (request) => {
      if (request.operation === "vault.status") return success(request, { unlocked: created, hasVault: created, itemCount: 0 });
      if (request.operation === "vault.create") { created = true; return success(request, { cancelled: false, status: { unlocked: true, hasVault: true, itemCount: 0 } }); }
      return previous(request);
    };
    await service.refresh();
    const command: SecurityCommand = { operation: "vault.create", input: { masterPassword: "synthetic-new-master" }, confirmed: true };
    expect(await service.securityTool(command)).toMatchObject({ ok: true }); expect(command.input.masterPassword).toBe("");
    expect(state.status).toBe("ready");
    expect(await service.securityTool({ operation: "vault.create", input: { masterPassword: "synthetic-another" }, confirmed: true })).toMatchObject({ ok: false });
    expect(requests.filter((request) => request.operation === "vault.create")).toHaveLength(1);
    expect(requests.find((request) => request.operation === "vault.create")!.input.confirmationToken).toBe(token);
  });
  it("CT-VAULT-002 rotates through the existing confirmed operation without replay after a lost result", async () => {
    const previous = reply;
    reply = async (request) => request.operation === "vault.change-password" ? Promise.reject(new Error("lost")) : previous(request);
    const command: SecurityCommand = { operation: "vault.change-password", input: { currentPassword: "synthetic-old", newPassword: "synthetic-new" }, confirmed: true };
    expect(await service.securityTool(command)).toEqual({ ok: false, code: "execution-unknown" });
    expect(command.input).toEqual({ currentPassword: "", newPassword: "" });
    expect(requests.filter((request) => request.operation === "vault.change-password")).toHaveLength(1);
  });
  it.each(["pin.status", "biometric.status", "browser.pairing.status", "password.health", "browser.fill.history", "vault.unlock-history", "security.settings.get"] as const)("reads %s only as validated metadata", async (operation) => {
    expect(await service.securityTool({ operation, input: {} })).toMatchObject({ ok: true });
    expect(requests.find((request) => request.operation === operation)!.input).toEqual({});
  });
  it("enables PIN through an independently authenticated operation and clears all outgoing PIN copies", async () => {
    const command: SecurityCommand = { operation: "pin.enable", input: { pin: "123456", failureLimit: 5 } };
    expect(await service.securityTool(command)).toMatchObject({ ok: true });
    expect(requests.find((request) => request.operation === "pin.enable")!.input).toMatchObject({ pin: "123456", userGestureId: expect.any(String) });
    expect(command.input.pin).toBe(""); expect(JSON.stringify(state)).not.toContain("123456");
  });
  it.each(["pin.unlock", "biometric.unlock"] as const)("%s works from the locked state without borrowing the desktop authorization", async (operation) => {
    unlocked = false; await service.refresh(); expect(state.status).toBe("locked");
    expect(await service.securityTool({ operation, input: operation === "pin.unlock" ? { pin: "123456" } : {} })).toMatchObject({ ok: true });
    expect(state.status).toBe("ready");
    expect(requests.filter((request) => request.operation === operation)).toHaveLength(1);
  });
  it("does not expose arbitrary commands or accept malformed PIN/settings input", () => {
    for (const command of [{ operation: "vault.restore", input: {} }, { operation: "pin.enable", input: { pin: "123", failureLimit: 5 } },
      { operation: "security.settings.update", input: { ...DEFAULT_SECURITY_SETTINGS, localPath: "/not-allowed" } }, { operation: "browser.pairing.revoke", input: {} }]) {
      expect(SecurityCommandSchema.safeParse(command).success).toBe(false);
    }
  });
  it("revokes only through command-bound confirmation and does not retry a lost response", async () => {
    const previous = reply; reply = async (request) => request.operation === "browser.pairing.revoke" ? Promise.reject(new Error("lost")) : previous(request);
    expect(await service.securityTool({ operation: "browser.pairing.revoke", input: {}, confirmed: true })).toEqual({ ok: false, code: "execution-unknown" });
    const confirmation = requests.find((request) => request.operation === "confirmation.request")!;
    const revoke = requests.filter((request) => request.operation === "browser.pairing.revoke");
    expect(revoke).toHaveLength(1); expect(revoke[0].input).toEqual({ userGestureId: confirmation.input.userGestureId, confirmationToken: token });
  });
  it("rejects an expired one-use confirmation before revoking", async () => {
    const previous = reply; reply = async (request) => request.operation === "confirmation.request" ? success(request, { confirmationToken: token, expiresAt: new Date(Date.now() - 1).toISOString() }) : previous(request);
    expect(await service.securityTool({ operation: "browser.pairing.revoke", input: {}, confirmed: true })).toEqual({ ok: false, code: "operation-expired" });
    expect(requests.some((request) => request.operation === "browser.pairing.revoke")).toBe(false);
  });
  it("renders the actual quick-unlock controls backed by the service and clears PIN on hidden", async () => {
    unlocked = false; await service.refresh();
    await TestBed.configureTestingModule({ imports: [VaultMeshSecurityToolsComponent], providers: [provideNoopAnimations(),
      { provide: VaultMeshBrowserRpcService, useValue: service }, { provide: I18nService, useClass: VaultMeshI18nService }] }).compileComponents();
    const fixture = TestBed.createComponent(VaultMeshSecurityToolsComponent); fixture.componentRef.setInput("locked", true); fixture.detectChanges();
    for (let i = 0; i < 150 && fixture.componentInstance["busy"](); i++) await Promise.resolve(); fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('input[name="pluginPin"]')).not.toBeNull();
    fixture.componentInstance["pin"] = "123456"; const hidden = jest.spyOn(document, "hidden", "get").mockReturnValue(true);
    document.dispatchEvent(new Event("visibilitychange")); expect(fixture.componentInstance["pin"]).toBe(""); hidden.mockRestore(); fixture.destroy();
  });
});

describe("CT-BROWSER-003 schema-bounded independent preferences", () => {
  it("persists only policy values under the independent key and rejects secrets", async () => {
    let stored: Record<string, unknown> = {};
    const get = jest.spyOn(chrome.storage.local, "get").mockImplementation((_key: any, callback: any) => callback(stored));
    const set = jest.spyOn(chrome.storage.local, "set").mockImplementation((value: any, callback: any) => { stored = value; callback(); });
    try {
      expect(await loadPluginPolicy()).toEqual(DEFAULT_PLUGIN_POLICY);
      expect(await savePluginPolicy({ ...DEFAULT_PLUGIN_POLICY, idleTimeoutMinutes: 10 })).toBe(true);
      expect(stored).toEqual({ [PLUGIN_POLICY_KEY]: { ...DEFAULT_PLUGIN_POLICY, idleTimeoutMinutes: 10 } });
      expect(await savePluginPolicy({ ...DEFAULT_PLUGIN_POLICY, password: "forbidden" } as any)).toBe(false);
      stored = { [PLUGIN_POLICY_KEY]: { idleTimeoutMinutes: -1 } }; expect(await loadPluginPolicy()).toEqual(DEFAULT_PLUGIN_POLICY);
    } finally { get.mockRestore(); set.mockRestore(); }
  });
});
