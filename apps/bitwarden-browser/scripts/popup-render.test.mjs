import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { JSDOM, VirtualConsole } from "jsdom";

const build = fileURLToPath(new URL("../build/", import.meta.url));
const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

test("CT-BROWSER-001 built startup feedback is immediate", () => {
  const css = fs.readFileSync(path.join(build, "popup/main.css"), "utf8");
  assert.doesNotMatch(css, /vm-deferred-loading|vm-show-loading/);
  assert.match(fs.readFileSync(path.join(build, "popup/index.html"), "utf8"), /id="loading"/);
  assert.doesNotMatch(fs.readFileSync(path.join(build, "popup/index.html"), "utf8"), /id="loading" class="vm-deferred-loading"/);
});

for (const [pinEnabled, biometricEnabled, expected] of [[false, false, "password"], [true, false, "pin"], [false, true, "biometric"], [true, true, "pin"]]) {
  test(`CT-SEC-002 built locked popup selects ${expected} (PIN ${pinEnabled}, biometric ${biometricEnabled})`, { timeout: 15000 }, async () => {
    const errors = [], operations = [];
    const output = new VirtualConsole();
    output.on("error", () => errors.push("popup-runtime-error"));
    output.on("jsdomError", () => errors.push("popup-dom-error"));
    const dom = new JSDOM(fs.readFileSync(path.join(build, "popup/index.html"), "utf8"), {
      url: "chrome-extension://edggbpbfcfagdnhiameocjapmggojhka/popup/index.html",
      runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: output,
    });
    const win = dom.window;
    const event = () => ({ addListener() {}, removeListener() {} });
    win.chrome = {
      i18n: { getUILanguage: () => "zh-CN", getMessage: id => id },
      runtime: {
        id: "synthetic", onMessage: event(), getURL: value => `chrome-extension://synthetic/${value}`,
        sendMessage(message, reply) {
          if (message.kind === "vaultmesh.browser-status") {
            setTimeout(() => reply({ kind: message.kind, status: "locked", vault: { hasVault: true, unlocked: false, itemCount: 0 } }), 0);
          } else if (message.action === "security-tool" && ["pin.status", "biometric.status"].includes(message.command.operation)) {
            const operation = message.command.operation;
            operations.push(operation);
            setTimeout(() => reply({ kind: message.kind, ok: true, result: operation === "pin.status"
              ? { enabled: pinEnabled, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 }
              : { enabled: biometricEnabled, available: biometricEnabled, kind: biometricEnabled ? "touchId" : null } }), 0);
          } else throw new Error("Unexpected operation in read-only unlock fixture");
        },
      },
      webNavigation: { onCommitted: event(), onHistoryStateUpdated: event(), onReferenceFragmentUpdated: event() },
      storage: { local: { get(_key, reply) { reply({}); }, set(_values, reply) { reply(); } } },
    };
    win.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} });
    win.TextEncoder = TextEncoder; win.TextDecoder = TextDecoder;
    win.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
    try {
      for (const script of win.document.querySelectorAll("script[src]")) {
        win.eval(fs.readFileSync(path.resolve(build, "popup", script.getAttribute("src")), "utf8"));
      }
      await wait(500);
      const unlock = win.document.querySelector("vaultmesh-unlock");
      assert.ok(unlock?.querySelector("bit-card"));
      assert.equal(!!unlock.querySelector('input[name="pluginUnlockPin"]'), expected === "pin");
      assert.equal(!!unlock.querySelector('input[name="masterPassword"]'), expected === "password");
      assert.equal(unlock.textContent.includes("指纹"), biometricEnabled);
      assert.equal(unlock.textContent.includes("PIN"), pinEnabled);
      assert.doesNotMatch(unlock.textContent, /PIN \/ 生物识别解锁/);
      if (expected !== "password") {
        [...unlock.querySelectorAll("button")].find(button => button.textContent.trim() === "改用主密码").click();
        await wait(50);
        assert.ok(unlock.querySelector('input[name="masterPassword"]'));
      }
      assert.deepEqual(operations, ["pin.status", "biometric.status"], "opening and switching must never authenticate automatically");
      assert.deepEqual(errors, []);
    } finally { win.close(); }
  });
}

test("CT-BROWSER-001 built popup bounds 521 synthetic rows and searches beyond the current page", { timeout: 20000 }, async () => {
  const errors = [];
  const output = new VirtualConsole();
  output.on("error", () => errors.push("popup-runtime-error"));
  output.on("jsdomError", () => errors.push("popup-dom-error"));
  const dom = new JSDOM(fs.readFileSync(path.join(build, "popup/index.html"), "utf8"), {
    url: "chrome-extension://edggbpbfcfagdnhiameocjapmggojhka/popup/index.html",
    runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: output,
  });
  const win = dom.window;
  // jsdom does not fetch linked CSS. Exercise the actual emitted collapse rule,
  // rather than only asserting that a Tailwind class appears in the template.
  const css = fs.readFileSync(path.join(build, "popup/main.css"), "utf8");
  const collapseRule = css.match(/[^{}]*:not\(:has\(>\s*\*\)\)\s*\{\s*display:\s*none;?\s*\}/)?.[0];
  assert.ok(collapseRule, "the empty-slot collapse rule must be emitted in the build");
  const layoutStyle = win.document.createElement("style");
  layoutStyle.textContent = collapseRule;
  win.document.head.appendChild(layoutStyle);
  const operations = [];
  const event = () => ({ addListener() {}, removeListener() {} });
  const summaries = Array.from({ length: 521 }, (_, index) => ({
    id: randomUUID(), title: `Synthetic ${index}`, username: "synthetic", url: null,
    hasPassword: true, hasTotpSecret: false, hasRecoveryCodes: false,
    autofillOnPageLoad: false, masterPasswordReprompt: false,
  }));
  win.chrome = {
    i18n: { getUILanguage: () => "zh-CN", getMessage: id => id },
    runtime: {
      id: "synthetic", onMessage: event(), getURL: value => `chrome-extension://synthetic/${value}`,
      sendMessage(message, reply) {
        operations.push(message.action ?? message.kind);
        if (message.kind === "vaultmesh.browser-status") {
          setTimeout(() => reply({ kind: message.kind, status: "ready", sessionId: "00000000-0000-4000-8000-000000000001", revision: 0, vault: { hasVault: true, unlocked: true, itemCount: summaries.length } }), 0);
        } else if (message.kind === "vaultmesh.browser-session" && message.action === "logins") {
          setTimeout(() => reply({ kind: message.kind, ok: true, result: summaries }), 0);
        } else if (message.kind === "vaultmesh.browser-session" && message.action === "login-detail") {
          const item = summaries.find(row => row.id === message.id);
          setTimeout(() => reply({ kind: message.kind, ok: true, result: { ...item,
            notes: null, folder: null, favorite: false, additionalUrls: [],
            customFields: [{ label: "Synthetic field", value: "synthetic-draft-canary" }],
          } }), 0);
        } else throw new Error("Unexpected operation in read-only popup fixture");
      },
    },
    webNavigation: { onCommitted: event(), onHistoryStateUpdated: event(), onReferenceFragmentUpdated: event() },
    storage: { local: { get(_key, reply) { reply({}); }, set(_values, reply) { reply(); } } },
  };
  win.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} });
  win.TextEncoder = TextEncoder; win.TextDecoder = TextDecoder;
  win.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
  const rows = () => win.document.querySelectorAll("bit-item");
  const next = () => [...win.document.querySelectorAll("button")].find(button => button.textContent.trim() === "下一页");
  try {
    for (const script of win.document.querySelectorAll("script[src]")) {
      const filename = path.resolve(build, "popup", script.getAttribute("src"));
      assert.ok(filename.startsWith(`${build}${path.sep}`) || filename.startsWith(build));
      win.eval(fs.readFileSync(filename, "utf8"));
    }
    await wait(500);
    const filterSlot = win.document.querySelector('[slot="above-scroll-area"]');
    assert.ok(filterSlot?.querySelector('select[aria-label="条目类型"]'));
    const filterWrapper = filterSlot.parentElement;
    assert.equal(filterWrapper.classList.contains("tw-invisible"), false, "first-load filters must be visible before any scroll");
    assert.equal(filterWrapper.classList.contains("tw-hidden"), false);
    assert.equal(filterWrapper.classList.contains("!tw-p-0"), false);
    assert.notEqual(win.getComputedStyle(filterWrapper).display, "none");
    assert.equal(rows().length, 25);
    assert.ok(win.document.querySelectorAll("button").length <= 90);
    assert.ok(win.document.querySelector("popup-tab-navigation bit-bottom-navigation"));
    assert.ok(win.document.querySelector("popup-page popup-header"));
    assert.match(win.document.body.textContent, /共 521 条/);
    next().click(); await wait(100);
    assert.match(rows()[0].textContent, /Synthetic 25/);
    const search = win.document.querySelector('input[type="search"]');
    search.value = "Synthetic 520"; search.dispatchEvent(new win.Event("input", { bubbles: true }));
    await wait(100);
    assert.equal(rows().length, 1); assert.match(rows()[0].textContent, /Synthetic 520/);
    win.document.querySelector('button[aria-label="更多选项 Synthetic 520"]').click(); await wait(100);
    const menu = win.document.querySelector('[role="menu"]');
    assert.ok(menu, "native item menu must open");
    assert.match(menu.textContent, /复制密码/);
    [...menu.querySelectorAll("button")].find(button => button.textContent.trim() === "查看").click(); await wait(100);
    assert.ok(win.document.querySelector('section[aria-label="条目详情"]'));
    assert.equal(filterWrapper.matches(":not(:has(>*))"), true);
    assert.ok(filterWrapper.classList.contains("[&:not(:has(>*))]:tw-hidden"), "removed filters must collapse instead of reserving space");
    assert.equal(win.getComputedStyle(filterWrapper).display, "none");
    assert.equal(operations.filter(action => action === "login-detail").length, 0, "summary view must not fetch protected detail");
    [...win.document.querySelectorAll("button")].find(button => button.textContent.trim() === "编辑").click(); await wait(100);
    assert.equal(operations.filter(action => action === "login-detail").length, 1);
    assert.ok([...win.document.querySelectorAll("input")].some(input => input.value === "synthetic-draft-canary"));
    const route = label => [...win.document.querySelectorAll("bit-bottom-navigation button")].find(button => button.textContent.trim() === label);
    route("generator").click(); await wait(100);
    assert.ok(win.document.querySelector("vaultmesh-generator bit-toggle-group"));
    assert.equal(win.document.querySelector("vaultmesh-login-editor"), null);
    assert.equal([...win.document.querySelectorAll("input")].some(input => input.value === "synthetic-draft-canary"), false);
    win.document.querySelector('vaultmesh-generator button[aria-label="生成"]').click(); await wait(100);
    const colored = win.document.querySelector("bit-color-password");
    assert.ok(colored?.querySelector("[data-password-character]"));
    const copy = new win.Event("copy", { bubbles: true, cancelable: true });
    colored.dispatchEvent(copy);
    assert.equal(copy.defaultPrevented, true, "native password display must not write the browser clipboard");
    route("settings").click(); await wait(100);
    assert.ok(win.document.querySelector('a[href="/account-security"]'));
    assert.equal(win.document.querySelector("vaultmesh-generator"), null);
    route("vault").click(); await wait(100);
    assert.equal(rows().length, 25);
    assert.equal(win.document.querySelector('input[type="search"]').value, "");
    const returnedFilter = win.document.querySelector('[slot="above-scroll-area"]').parentElement;
    assert.equal(returnedFilter.classList.contains("tw-invisible"), false);
    assert.notEqual(win.getComputedStyle(returnedFilter).display, "none");
    assert.equal(win.location.hash, "", "routes must not change the editor's exact document URL");
    assert.equal(win.document.querySelector("vaultmesh-login-editor"), null);
    assert.doesNotMatch(win.document.body.textContent, /导入保险库|备份保险库|Send/);
    const listReads = operations.filter(action => action === "logins").length;
    const statusReads = operations.filter(action => action === "vaultmesh.browser-status").length;
    await wait(3200);
    assert.ok(operations.filter(action => action === "vaultmesh.browser-status").length > statusReads, "polls must still revalidate authorization");
    assert.equal(operations.filter(action => action === "logins").length, listReads, "unchanged polls must not reread all summaries");
    assert.deepEqual(errors, []);
  } finally { dom.window.close(); }
});
