import { describe, expect, it } from "vitest";
import { inlineMenuLayout } from "./inline-menu-layout";

describe("CT-AUTOFILL-003 in-frame menu bounds", () => {
  it("uses a bounded scrollable overlay in a short and narrow iframe", () => {
    expect(inlineMenuLayout({ left: 100, right: 180, top: 40, bottom: 72, width: 80 }, { width: 200, height: 110 }))
      .toEqual({ left: 8, width: 184, top: 8, bottom: undefined, maxHeight: 94 });
  });
  it("opens above when the lower edge has no space", () => {
    expect(inlineMenuLayout({ left: 20, right: 260, top: 500, bottom: 530, width: 240 }, { width: 800, height: 550 }))
      .toMatchObject({ top: undefined, bottom: 496, maxHeight: 280 });
  });
  it("respects visual viewport offsets and hides offscreen anchors", () => {
    const rect = { left: 20, right: 260, top: 200, bottom: 230, width: 240 };
    const layout = inlineMenuLayout(rect, { width: 300, height: 200, left: 50, top: 180 })!;
    expect(layout.left).toBe(58);
    expect(layout.top! + layout.maxHeight).toBeLessThanOrEqual(372);
    expect(inlineMenuLayout(rect, { width: 300, height: 100 })).toBeNull();
  });
});
