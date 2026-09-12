import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { JSDOM, VirtualConsole } from "jsdom";

test("CT-AUTOFILL-001 built content collects without disclosing field values and rejects invalidated assignments", { timeout: 15000 }, async () => {
  const errors = [], listeners = [];
  const output = new VirtualConsole();
  output.on("error", () => errors.push("content-error"));
  output.on("jsdomError", () => errors.push("content-dom-error"));
  const dom = new JSDOM('<form><input name="username" autocomplete="username" value="synthetic-local-canary"><input name="password" type="password" autocomplete="current-password"></form>', {
    url: "https://example.test/login", pretendToBeVisual: true, runScripts: "outside-only", virtualConsole: output,
  });
  const win = dom.window;
  win.TextEncoder = TextEncoder; win.TextDecoder = TextDecoder;
  win.IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} };
  win.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
  win.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {} });
  // Deterministic geometry for this DOM-only regression, not a real browser layout claim.
  win.HTMLElement.prototype.getBoundingClientRect = function() {
    const top = this.getAttribute("name") === "password" ? 60 : 10;
    return { x: 10, y: top, top, left: 10, bottom: top + 30, right: 210, width: 200, height: 30 };
  };
  win.HTMLElement.prototype.getClientRects = function() { return [this.getBoundingClientRect()]; };
  Object.defineProperties(win.document.documentElement, { scrollWidth: { value: 1024 }, scrollHeight: { value: 768 } });
  win.document.elementFromPoint = (_x, y) => win.document.querySelector(y >= 60 ? '[name="password"]' : '[name="username"]');
  win.chrome = {
    runtime: { id: "synthetic", getURL: value => `chrome-extension://synthetic/${value}`,
      onMessage: { addListener: listener => listeners.push(listener), removeListener() {} },
      sendMessage(message, reply) { reply?.(message.kind === "vaultmesh.native-fill.check" ? true : null); },
    },
    i18n: { getMessage: id => id },
    storage: { local: { get(_key, reply) { reply({}); }, set(_values, reply) { reply?.(); } } },
  };
  const request = message => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("content-response-timeout")), 3000);
    const reply = value => { clearTimeout(timer); resolve(value); };
    let handled = false;
    for (const listener of listeners) handled = listener(message, { id: "synthetic" }, reply) || handled;
    if (!handled && message.kind !== "vaultmesh.native-fill.cancel") { clearTimeout(timer); reject(new Error("content-listener-missing")); }
  });
  try {
    const script = fs.readFileSync(new URL("../build/content/vaultmesh-native-fill.js", import.meta.url), "utf8");
    win.eval(script);
    // Startup capture observers finish their shared read before an explicit request.
    await new Promise(resolve => setTimeout(resolve, 25));
    const page = await request({ kind: "vaultmesh.native-fill.collect", requestId: randomUUID(), topOrigin: "https://example.test" });
    assert.equal(page?.fields.length, 2);
    assert.doesNotMatch(JSON.stringify(page), /synthetic-local-canary/);
    assert.ok(page.fields.every(field => typeof field.empty === "boolean" && !("value" in field)));
    const assignmentFor = snapshot => {
      const field = snapshot.fields.find(field => field.type === "password");
      return { kind: "vaultmesh.native-fill.apply", script: [["fill_by_opid", field.opid, "password"]],
        assignment: { kind: "vaultmesh.approved-fill", requestId: snapshot.requestId, tabId: 7,
          topOrigin: "https://example.test", expiresAt: snapshot.expiresAt,
          selectedItem: { kind: "login", id: randomUUID(), title: "Synthetic" },
          frames: [{ frameId: 0, documentId: snapshot.documentId, frameOrigin: "https://example.test",
            assignments: [{ handle: field.handle, value: "synthetic-password", overwrite: false }] }] } };
    };
    await request({ kind: "vaultmesh.native-fill.cancel" });
    const result = await request(assignmentFor(page));
    assert.equal(result, null);
    assert.equal(win.document.querySelector('[name="password"]').value, "");
    const fresh = await request({ kind: "vaultmesh.native-fill.collect", requestId: randomUUID(), topOrigin: "https://example.test" });
    assert.equal((await request(assignmentFor(fresh)))?.filled, 1);
    assert.equal(win.document.querySelector('[name="password"]').value, "synthetic-password");
    assert.deepEqual(errors, []);
  } finally { win.close(); }
});
