import { TestBed } from "@angular/core/testing";
import { BehaviorSubject } from "rxjs";
import { VaultMeshManagedItemsComponent } from "./managed-items.component";
import { VaultMeshBrowserRpcService } from "../platform/services/vaultmesh-browser-rpc.service";

describe("CT-BROWSER-001 native managed lists", () => {
  afterEach(() => TestBed.resetTestingModule());

  it.each(["card", "identity", "ssh", "secret"] as const)("bounds %s controls, searches the whole collection and clears on lock", async kind => {
    const rows = Array.from({ length: 521 }, (_, index) => ({ id: `synthetic-${index}`, title: `Synthetic ${index}` }));
    const state$ = new BehaviorSubject({ status: "ready", sessionId: "synthetic", revision: 1 });
    const service = { state$, managedItem: jest.fn().mockResolvedValue({ ok: true, value: rows }), cancelManaged: jest.fn() };
    TestBed.configureTestingModule({ providers: [{ provide: VaultMeshBrowserRpcService, useValue: service }] });
    const component = TestBed.runInInjectionContext(() => new VaultMeshManagedItemsComponent());
    component.kind = kind; component.ngOnInit(); await Promise.resolve();
    expect(component["visibleRows"]()).toHaveLength(25);
    component["changePage"](99);
    expect(component["visibleRows"]().at(-1)?.title).toBe("Synthetic 520");
    component["setQuery"]("Synthetic 520");
    expect(component["visibleRows"]()).toHaveLength(1);
    expect(component["currentPage"]()).toBe(0);
    state$.next({ ...state$.value, status: "locked" });
    expect(component["visibleRows"]()).toEqual([]);
    expect(component["query"]).toBe("");
    component.ngOnDestroy();
  });
});
