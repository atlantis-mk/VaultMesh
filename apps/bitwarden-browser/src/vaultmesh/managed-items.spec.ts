import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { BehaviorSubject } from "rxjs";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { VaultMeshI18nService } from "./i18n.service";
import { VaultMeshManagedItemsComponent } from "./managed-items.component";
import { VaultMeshBrowserRpcService, type SessionState } from "../platform/services/vaultmesh-browser-rpc.service";
import { ManagedDraft } from "./managed-draft";
import { ManagedCommandSchema, MANAGED_ITEMS, parseManagedResult, managedRequest, type ManagedKind, type ManagedCommand } from "./managed-items";

export const managedId = "00000000-0000-4000-8000-000000000025";
export function managedFixture(kind: ManagedKind): Record<string, unknown> {
  const draft = new ManagedDraft(kind);
  Object.assign(draft.data, { title: "Synthetic item", ...(kind === "card" ? { cardholderName: "Example", cardNumber: "4242424242424242", expirationMonth: 12, expirationYear: 2030 }
    : kind === "ssh" ? { host: "example.test", username: "user", password: "synthetic-secret" }
    : kind === "secret" ? { secret: "synthetic-secret" } : {}) });
  const input = draft.toInput();
  return { ...input, id: managedId, maskedNumber: "••••4242", hasSecurityCode: false, hasPin: false,
    displayName: "Example", hasPassword: true, hasPublicKey: false, hasPrivateKey: false, hasKeyPassphrase: false,
    keyAlgorithm: null, publicKeyFingerprint: null, managedSshAlias: null, isPasskey: false, loginId: null };
}

describe("CT-ITEM-002/003/004/005 desktop-owned item projections", () => {
  it.each<ManagedKind>(["card", "identity", "ssh", "secret"])("%s edits preserve unread secrets and metadata", (kind) => {
    const detail = MANAGED_ITEMS[kind].detail.parse(managedFixture(kind));
    const draft = new ManagedDraft(kind, detail);
    draft.data.title = "Renamed";
    const input = draft.toInput();
    expect(input.id).toBe(managedId);
    expect(input.title).toBe("Renamed");
    if (kind === "card") expect(input).toMatchObject({ cardNumber: null, securityCode: null, pin: null, clearPin: false, clearSecurityCode: false });
    if (kind === "ssh") expect(input).toMatchObject({ password: null, publicKey: null, privateKey: null, keyPassphrase: null, recordKind: "account", clearPassword: false });
    if (kind === "secret") expect(input.secret).toBeNull();
    expect(ManagedCommandSchema.safeParse({ kind, verb: "save", input }).success).toBe(true);
    draft.clear(); expect(() => draft.toInput()).toThrow("expired-draft");
  });
  it("preserves all identity values, IDs and address fields through a partial metadata edit", () => {
    const draft = new ManagedDraft("identity"); draft.data.title = "Person";
    draft.add("emails"); draft.add("phones"); draft.add("addresses");
    draft.data.emails[0].value = "person@example.test"; draft.data.phones[0].value = "+12025550100";
    draft.data.addresses[0].addressLine1 = "Synthetic Street"; draft.data.addresses[0].countryCode = "US";
    const input = draft.toInput();
    const edited = new ManagedDraft("identity", { ...input, id: managedId }); edited.data.title = "Renamed";
    expect(edited.toInput()).toMatchObject({ emails: input.emails, phones: input.phones, addresses: input.addresses });
    const addresses = edited.data.addresses; edited.clear(); expect(addresses[0].addressLine1).toBe("");
  });
  it("rejects unsupported routes, copy fields, caller tokens and conflicting secret replacements", () => {
    expect(ManagedCommandSchema.safeParse({ kind: "secret", verb: "trash" }).success).toBe(false);
    expect(ManagedCommandSchema.safeParse({ kind: "identity", verb: "copy", id: managedId, field: "private-key" }).success).toBe(false);
    expect(ManagedCommandSchema.safeParse({ kind: "card", verb: "delete", id: managedId, confirmed: true, confirmationToken: managedId }).success).toBe(false);
    const input = new ManagedDraft("card", MANAGED_ITEMS.card.detail.parse(managedFixture("card"))).toInput();
    expect(ManagedCommandSchema.safeParse({ kind: "card", verb: "save", input: { ...input, securityCode: "123", clearSecurityCode: true } }).success).toBe(false);
    expect(ManagedCommandSchema.safeParse({ kind: "card", verb: "save", input: { ...input, localPath: "/not-allowed" } }).success).toBe(false);
  });
  it("projects out secrets, filters Passkeys and rejects wrong response targets", () => {
    expect(parseManagedResult({ kind: "secret", verb: "list" }, [managedFixture("secret"), { ...managedFixture("secret"), isPasskey: true }])).toHaveLength(1);
    const result = parseManagedResult({ kind: "card", verb: "detail", id: managedId }, managedFixture("card"));
    expect(JSON.stringify(result)).not.toContain("4242424242424242");
    expect(() => parseManagedResult({ kind: "ssh", verb: "detail", id: managedId }, { ...managedFixture("ssh"), id: "00000000-0000-4000-8000-000000000026" })).toThrow();
  });
  it.each<ManagedKind>(["card", "identity", "ssh", "secret"])("%s exposes only its registered command prefix", (kind) => {
    expect(managedRequest({ kind, verb: "list" }).operation).toBe(`${MANAGED_ITEMS[kind].prefix}.list`);
  });
});

describe("CT-BROWSER-001 / CT-RECOVERY-001 real managed editor rendering and lifetime", () => {
  afterEach(() => { TestBed.resetTestingModule(); jest.useRealTimers(); });
  async function setup(kind: ManagedKind) {
    const state$ = new BehaviorSubject<SessionState>({ status: "ready", vault: null, logins: [], busy: false, error: null, revision: 0, sessionId: managedId });
    const service = { state$, cancelManaged: jest.fn(), managedItem: jest.fn(async (command: ManagedCommand) => ({ ok: true, value: command.verb === "list" ? [] : null })) };
    await TestBed.configureTestingModule({ imports: [VaultMeshManagedItemsComponent], providers: [provideNoopAnimations(),
      { provide: VaultMeshBrowserRpcService, useValue: service }, { provide: I18nService, useClass: VaultMeshI18nService }] }).compileComponents();
    const fixture = TestBed.createComponent(VaultMeshManagedItemsComponent); fixture.componentRef.setInput("kind", kind);
    fixture.detectChanges();
    // The live component intentionally owns a five-minute expiry timer; drain
    // the initial read, not Angular's long-lived timer queue.
    await Promise.resolve(); await Promise.resolve(); fixture.detectChanges();
    return { fixture, service, state$, component: fixture.componentInstance };
  }
  it.each<ManagedKind>(["card", "identity", "ssh", "secret"])("renders %s controls and clears a draft on lock", async (kind) => {
    const { fixture, component, state$ } = await setup(kind);
    component["create"](); fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('input[name="title"]')).not.toBeNull();
    const draft = component["draft"]()!; draft.data.title = "Transient";
    if (kind === "identity") { fixture.nativeElement.querySelector('fieldset button').click(); fixture.detectChanges(); expect(fixture.nativeElement.querySelector('input[name="emails0value"]')).not.toBeNull(); }
    state$.next({ ...state$.value, status: "locked" }); fixture.detectChanges();
    expect(component["draft"]()).toBeNull(); expect(draft.data.title).toBe(""); fixture.destroy();
  });
  it("requires explicit confirmation and expires it without making a write", async () => {
    const { fixture, component, service } = await setup("card"); jest.useFakeTimers();
    component["askDelete"]({ id: managedId, title: "Synthetic" }); fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain("并移至回收站");
    expect(service.managedItem).toHaveBeenCalledTimes(1);
    jest.advanceTimersByTime(30001); await component["confirm"]();
    expect(service.managedItem).toHaveBeenCalledTimes(1); fixture.destroy();
  });
  it("clears ordinary blur and rejects late detail without resurrecting an editor", async () => {
    const { fixture, component, service } = await setup("card"); fixture.componentRef.setInput("independent", true); fixture.detectChanges();
    let resolve!: (value: any) => void;
    service.managedItem.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    const pending = component["edit"]({ id: managedId, title: "Synthetic" });
    window.dispatchEvent(new Event("blur")); resolve({ ok: true, value: managedFixture("card") }); await pending;
    expect(component["draft"]()).toBeNull(); expect(service.cancelManaged).toHaveBeenCalled(); fixture.destroy();
  });
});
