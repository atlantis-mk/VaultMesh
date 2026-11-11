import { describe, expect, it } from "vitest";

import { sameOriginFrameIds, sameOriginWithAncestors } from "./frame-origin";

describe("sameOriginFrameIds", () => {
  it("includes nested about:srcdoc and about:blank frames that inherit the top origin", () => {
    const frames = [
      { frameId: 0, parentFrameId: -1, url: "https://example.test/account" },
      { frameId: 2, parentFrameId: 0, url: "about:srcdoc" },
      { frameId: 3, parentFrameId: 2, url: "about:blank" },
    ];

    expect(sameOriginFrameIds(frames, "https://example.test")).toEqual([0, 2, 3]);
  });

  it("excludes cross-origin and non-inheriting opaque frames", () => {
    const frames = [
      { frameId: 0, parentFrameId: -1, url: "https://example.test/account" },
      { frameId: 2, parentFrameId: 0, url: "https://other.test/login" },
      { frameId: 3, parentFrameId: 0, url: "data:text/html,login" },
    ];

    expect(sameOriginFrameIds(frames, "https://example.test")).toEqual([0]);
  });
});

describe("sameOriginWithAncestors", () => {
  const frames = [
    { frameId: 0, parentFrameId: -1, url: "https://example.test/account" },
    { frameId: 1, parentFrameId: 0, url: "https://example.test/embedded" },
    { frameId: 2, parentFrameId: 0, url: "https://other.test/widget" },
    { frameId: 3, parentFrameId: 2, url: "https://example.test/nested" },
    { frameId: 4, parentFrameId: 0, url: "about:blank" },
  ];

  it("accepts the top frame, same-origin children and inheriting blank frames", () => {
    for (const frameId of [0, 1, 4]) expect(sameOriginWithAncestors(frames, frameId, "https://example.test")).toBe(true);
  });

  it("rejects cross-origin frames and same-origin frames below a cross-origin ancestor", () => {
    expect(sameOriginWithAncestors(frames, 2, "https://example.test")).toBe(false);
    expect(sameOriginWithAncestors(frames, 3, "https://example.test")).toBe(false);
  });

  it("fails closed for unknown frames, missing ancestors and cycles", () => {
    expect(sameOriginWithAncestors(frames, 99, "https://example.test")).toBe(false);
    expect(sameOriginWithAncestors([{ frameId: 5, parentFrameId: 9, url: "https://example.test/" }], 5, "https://example.test")).toBe(false);
    expect(sameOriginWithAncestors([{ frameId: 5, parentFrameId: 6, url: "https://example.test/" }, { frameId: 6, parentFrameId: 5, url: "https://example.test/" }], 5, "https://example.test")).toBe(false);
  });
});
