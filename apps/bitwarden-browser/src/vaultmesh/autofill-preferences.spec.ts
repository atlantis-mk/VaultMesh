import { AutofillPreferences, automaticCandidate } from "./autofill-preferences";
import type { NativeCandidate } from "./native-fill-contracts";
const first = "33333333-3333-4333-8333-333333333333";
const second = "44444444-4444-4444-8444-444444444444";
const candidate = (id: string, matchScope = "origin"): NativeCandidate => ({ id, matchScope, kind: "login", title: "Synthetic", subtitle: "synthetic-user", autofillOnPageLoad: true, masterPasswordReprompt: false });

describe("CT-BROWSER-003 nonsecret autofill preferences", () => {
  it("persists only origin and opaque ID and keeps different ports separate", async () => {
    const stored: Record<string, unknown> = {};
    (chrome.storage.local.get as jest.Mock).mockImplementation((key, callback) => callback({ [key]: stored[key] }));
    (chrome.storage.local.set as jest.Mock).mockImplementation((value, callback) => { Object.assign(stored, value); callback(); });
    await new AutofillPreferences().remember("https://synthetic.test:8443", first);
    expect(await new AutofillPreferences().remembered("https://synthetic.test:8443")).toBe(first);
    expect(await new AutofillPreferences().remembered("https://synthetic.test")).toBeUndefined();
    expect(Object.values(stored)).toEqual([[{ origin: "https://synthetic.test:8443", id: first }]]);
    await new AutofillPreferences().remember("file:///synthetic", first);
    expect(Object.values(stored)).toHaveLength(1);
  });
  it("rejects unexpected persisted fields instead of treating secret-bearing objects as settings", async () => {
    (chrome.storage.local.get as jest.Mock).mockImplementation((key, callback) => callback({ [key]: [{ origin: "https://synthetic.test", id: first, password: "synthetic-secret" }] }));
    expect(await new AutofillPreferences().remembered("https://synthetic.test")).toBeUndefined();
  });
  it("serializes concurrent read-modify-write operations without losing another origin", async () => {
    const stored: Record<string, unknown> = {};
    (chrome.storage.local.get as jest.Mock).mockImplementation((key, callback) => queueMicrotask(() => callback({ [key]: stored[key] })));
    (chrome.storage.local.set as jest.Mock).mockImplementation((value, callback) => queueMicrotask(() => { Object.assign(stored, value); callback(); }));
    const prefs = new AutofillPreferences();
    await Promise.all([prefs.remember("https://first.test", first), prefs.remember("https://second.test", second)]);
    expect(await prefs.remembered("https://first.test")).toBe(first);
    expect(await prefs.remembered("https://second.test")).toBe(second);
    await Promise.all([prefs.remember("https://first.test", second), prefs.remember("https://first.test", first)]);
    expect(await prefs.remembered("https://first.test")).toBe(first);
  });
  it("ranks eligible path/origin/domain matches, honors remembered eligible IDs and rejects ambiguous ties", () => {
    expect(automaticCandidate([candidate(first), candidate(second)])).toBeUndefined();
    expect(automaticCandidate([candidate(first), candidate(second, "path")])?.id).toBe(second);
    expect(automaticCandidate([candidate(first), candidate(second, "path")], first)?.id).toBe(first);
    expect(automaticCandidate([{ ...candidate(first), masterPasswordReprompt: true }, candidate(second)], first)?.id).toBe(second);
    expect(automaticCandidate([{ ...candidate(first), autofillOnPageLoad: false }], first)).toBeUndefined();
    expect(automaticCandidate([candidate(first, "unknown")], first)).toBeUndefined();
  });
});
