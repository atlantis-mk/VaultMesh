import { PopupLocationStrategy } from "./popup-location";

describe("CT-BROWSER-001 transient native page routing", () => {
  it("keeps the exact document URL and all route history out of browser storage", () => {
    const original = location.href;
    const locationStrategy = new PopupLocationStrategy();
    const changed = jest.fn();
    locationStrategy.onPopState(changed);
    locationStrategy.replaceState(null, "", "/tabs/vault", "");
    locationStrategy.pushState(null, "", "/tabs/generator", "");
    locationStrategy.pushState(null, "", "/tabs/settings", "");
    expect(locationStrategy.path()).toBe("/tabs/settings");
    locationStrategy.back();
    expect(locationStrategy.path()).toBe("/tabs/generator");
    expect(changed).toHaveBeenCalledWith({ type: "popstate", state: null });
    locationStrategy.forward();
    expect(locationStrategy.path()).toBe("/tabs/settings");
    expect(location.href).toBe(original);
    expect(new PopupLocationStrategy().path()).toBe("/");
  });
});
