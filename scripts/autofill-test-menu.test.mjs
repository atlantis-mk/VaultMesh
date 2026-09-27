import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { webcrypto, createPrivateKey, sign } from "node:crypto";
import test from "node:test";

const requireExtension = createRequire(new URL("../apps/browser-extension/package.json", import.meta.url));
const { JSDOM, VirtualConsole } = requireExtension("jsdom");
const html = await readFile(new URL("../autofill-test.html", import.meta.url), "utf8");
const suiteIds = [
  "save-capture-tests", "login-tests", "otp-tests", "passkey-tests", "card-tests",
  "identity-tests", "sensitive-item-tests", "account-lifecycle-tests", "runtime-tests",
  "device-assist-tests", "secret-types-tests", "capture-path-tests", "advanced-fields-tests",
  "lifecycle-tests", "authenticator-tests",
];
function page(suite = "") {
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (error) => errors.push(error.message));
  const dom = new JSDOM(html, {
    url: `https://localhost/autofill-test.html${suite ? `?suite=${suite}` : ""}`,
    runScripts: "dangerously", virtualConsole,
    beforeParse(window) { window.HTMLElement.prototype.scrollIntoView = () => {}; },
  });
  return { dom, window: dom.window, document: dom.window.document, errors };
}
function changed(window, control, value) {
  if (control.hasAttribute("contenteditable")) control.textContent = value;
  else control.value = value;
  for (const type of ["input", "change"]) control.dispatchEvent(new window.Event(type, { bubbles: true, composed: true }));
}

test("every suite routes to an isolated page with a checklist and no startup errors", () => {
  for (const suite of ["", ...suiteIds]) {
    const { dom, document, errors } = page(suite);
    try {
      assert.equal(document.querySelectorAll("[data-suite-card]").length, suiteIds.length);
      const ids = [...document.querySelectorAll("[id]")].map((node) => node.id);
      assert.equal(new Set(ids).size, ids.length, "duplicate fixture IDs");
      for (const id of suiteIds) {
        assert.ok(document.querySelector(`[data-suite-card="${id}"][href="?suite=${id}"]`));
        assert.equal(document.getElementById(id).hidden, id !== suite);
      }
      assert.equal(document.getElementById("acceptance-panel").hidden, !suite);
      if (suite) {
        assert.ok(document.querySelectorAll("[data-acceptance]").length);
        assert.equal(document.getElementById("manual-pass-button").disabled, true);
      }
      assert.deepEqual(errors, []);
    } finally { dom.window.close(); }
  }
});

test("Secret fixture kinds stay in parity with the capture contract", async () => {
  const contract = await readFile(new URL("../apps/browser-extension/src/lib/save-capture.ts", import.meta.url), "utf8");
  const kinds = [...contract.match(/export type CapturedSecret = \{[\s\S]*?kind: ([^;]+);/)[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]);
  const { dom, document } = page("secret-types-tests");
  try {
    assert.deepEqual([...document.querySelectorAll("[data-secret-kind]")].map((node) => node.dataset.secretKind).sort(), kinds.sort());
    for (const form of document.querySelectorAll("[data-secret-kind]")) {
      assert.equal(form.querySelectorAll("textarea").length, 1, "one unambiguous secret per form");
      assert.ok(form.querySelector('button[type="submit"]'));
    }
  } finally { dom.window.close(); }
});

test("field checks cannot mark a suite passed or disclose any field values", () => {
  const { dom, document, window } = page("advanced-fields-tests");
  try {
    for (const control of document.querySelectorAll('#advanced-fields-tests [data-vm-test]')) changed(window, control, "qa-sensitive-canary");
    document.getElementById("audit-button").click();
    assert.match(document.getElementById("result-summary").textContent, /4 \/ 4 PASS/);
    assert.match(document.getElementById("result-summary").textContent, /仍需人工/);
    assert.doesNotMatch(document.getElementById("results-body").textContent, /qa-sensitive-canary/);
    assert.doesNotMatch(document.getElementById("event-log").textContent, /qa-sensitive-canary/);
    assert.equal(window.sessionStorage.length, 0);
    assert.equal(document.getElementById("manual-pass-button").disabled, true);
  } finally { dom.window.close(); }
});

test("failed, blocked and incomplete checklists cannot pass; persistence contains only suite and timestamp", () => {
  const { dom, document, window } = page("lifecycle-tests");
  try {
    const selects = [...document.querySelectorAll("[data-acceptance]")];
    for (const select of selects) changed(window, select, "passed");
    const button = document.getElementById("manual-pass-button");
    for (const value of ["pending", "failed", "blocked"]) {
      changed(window, selects[0], value);
      assert.equal(button.disabled, true);
      button.click();
      assert.deepEqual(JSON.parse(window.sessionStorage.getItem("vaultmesh.qa.autofill.suite-status.v2")), {});
    }
    changed(window, selects[0], "passed");
    assert.equal(button.disabled, false);
    button.click();
    const state = JSON.parse(window.sessionStorage.getItem("vaultmesh.qa.autofill.suite-status.v2"));
    assert.deepEqual(Object.keys(state), ["lifecycle-tests"]);
    assert.ok(Number.isFinite(Date.parse(state["lifecycle-tests"])));
    changed(window, selects[0], "failed");
    assert.deepEqual(JSON.parse(window.sessionStorage.getItem("vaultmesh.qa.autofill.suite-status.v2")), {});
    assert.equal(window.localStorage.length, 0);
  } finally { dom.window.close(); }
});

test("external controls, SPA destruction and non-composed shadow submit exercise real DOM paths", () => {
  const { dom, document, window, errors } = page("capture-path-tests");
  try {
    assert.equal(document.getElementById("external-user").form.id, "external-form");
    assert.equal(document.getElementById("external-password").form.id, "external-form");
    document.getElementById("formdata-action").click();
    document.getElementById("spa-remove-action").click();
    assert.equal(document.querySelectorAll("#spa-remove-case input").length, 0);
    const root = document.getElementById("capture-shadow-host").shadowRoot;
    const event = new window.Event("submit", { bubbles: true, cancelable: true, composed: false });
    assert.equal(root.querySelector("form").dispatchEvent(event), false);
    assert.match(root.querySelector("p").textContent, /内部提交/);
    assert.deepEqual(errors, []);
  } finally { dom.window.close(); }
});

test("multistep login removes the account field and presents a password-only stage", async () => {
  const { dom, document, window, errors } = page("advanced-fields-tests");
  try {
    document.getElementById("step-user").value = "synthetic-account";
    const event = new window.Event("submit", { bubbles: true, cancelable: true });
    assert.equal(document.getElementById("account-step").dispatchEvent(event), false);
    await new Promise((resolve) => window.setTimeout(resolve, 10));
    assert.equal(document.getElementById("step-user"), null);
    assert.ok(document.getElementById("step-password"));
    assert.doesNotMatch(document.getElementById("multistep-slot").textContent, /synthetic-account/);
    assert.deepEqual(errors, []);
  } finally { dom.window.close(); }
});

test("lifecycle buttons really invalidate the old node, readonly eligibility and URL", () => {
  const { dom, document, window } = page("lifecycle-tests");
  try {
    const previous = document.getElementById("lifecycle-user"); previous.value = "qa-canary";
    document.getElementById("invalidate-target").click();
    assert.equal(previous.isConnected, false);
    assert.equal(document.getElementById("lifecycle-user").value, "");
    document.getElementById("readonly-target").click();
    assert.equal(document.getElementById("lifecycle-user").readOnly, true);
    document.getElementById("navigate-target").click();
    assert.match(window.location.hash, /^#qa-navigation-/);
  } finally { dom.window.close(); }
});

test("composed shadow input events are counted once and redacted", () => {
  const { dom, document, window } = page("runtime-tests");
  try {
    const root = document.getElementById("shadow-host").shadowRoot;
    changed(window, root.querySelector("input"), "qa-shadow-canary");
    assert.equal(document.getElementById("metric-events").textContent, "2");
    assert.doesNotMatch(document.getElementById("event-log").textContent, /qa-shadow-canary/);
  } finally { dom.window.close(); }
});

test("QR previews revoke object URLs, reject oversized input and can be hidden", () => {
  const { dom, document, window } = page("authenticator-tests");
  try {
    const revoked = []; window.URL.createObjectURL = () => "blob:qa-local"; window.URL.revokeObjectURL = (url) => revoked.push(url);
    const control = document.getElementById("qr-files");
    Object.defineProperty(control, "files", { configurable: true, value: [new window.File(["synthetic"], "qa.png", { type: "image/png" })] });
    control.dispatchEvent(new window.Event("change"));
    assert.equal(document.querySelectorAll("#qr-preview img").length, 1);
    document.getElementById("qr-hide").click();
    assert.equal(document.getElementById("qr-preview").hidden, true);
    document.getElementById("qr-clear").click();
    assert.deepEqual(revoked, ["blob:qa-local"]);
    assert.equal(document.querySelectorAll("#qr-preview img").length, 0);
    Object.defineProperty(control, "files", { value: [{ type: "image/png", size: 3 * 1024 * 1024 }] });
    control.dispatchEvent(new window.Event("change"));
    assert.equal(document.querySelectorAll("#qr-preview img").length, 0);
    assert.match(document.getElementById("qr-status").textContent, /不超过/);
  } finally { dom.window.close(); }
});

test("Passkey QA validates real ES256 signatures and rejects bad challenge, origin, RP, ID and signature", async () => {
  const helpers = html.slice(html.indexOf("      function base64url"), html.indexOf("      async function createPasskey"));
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const location = new URL("https://localhost/autofill-test.html");
  const id = Uint8Array.of(1, 2, 3);
  const { verifyAssertion } = new Function("crypto", "location", "passkeyVerificationKey", "passkeyCredentialId", `${helpers}; return { verifyAssertion };`)(webcrypto, location, keys.publicKey, id);
  const challenge = webcrypto.getRandomValues(new Uint8Array(32));
  const privateKey = createPrivateKey({ key: Buffer.from(await webcrypto.subtle.exportKey("pkcs8", keys.privateKey)), format: "der", type: "pkcs8" });
  async function assertion(overrides = {}) {
    const client = { type: "webauthn.get", origin: location.origin, challenge: Buffer.from(challenge).toString("base64url"), ...overrides.client };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(client));
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(new Uint8Array(await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(overrides.rp || location.hostname))));
    authenticatorData[32] = overrides.flags ?? 1;
    const clientHash = new Uint8Array(await webcrypto.subtle.digest("SHA-256", clientDataJSON));
    const signature = sign("sha256", Buffer.concat([authenticatorData, clientHash]), privateKey);
    if (overrides.corrupt) signature[signature.length - 1] ^= 1;
    return { rawId: overrides.id || id, response: { clientDataJSON, authenticatorData, signature } };
  }
  await verifyAssertion(await assertion(), challenge);
  for (const overrides of [{ client: { challenge: "wrong" } }, { client: { origin: "https://other.test" } }, { client: { crossOrigin: true } }, { rp: "other.test" }, { flags: 0 }, { id: Uint8Array.of(9) }, { corrupt: true }]) {
    await assert.rejects(verifyAssertion(await assertion(overrides), challenge));
  }
});

test("same-origin iframe realm events count correctly and submissions are observed without navigation", () => {
  const { dom, document, window, errors } = page("runtime-tests");
  try {
    const frame = document.getElementById("same-origin-frame");
    const child = frame.contentDocument;
    child.open();
    child.write('<form><input name="username" data-vm-test="iframe username" data-expect="fill"></form>');
    child.close();
    frame.dispatchEvent(new window.Event("load"));
    changed(frame.contentWindow, child.querySelector("input"), "qa-frame-canary");
    assert.equal(document.getElementById("metric-events").textContent, "2");
    const event = new frame.contentWindow.Event("submit", { bubbles: true, cancelable: true });
    assert.equal(child.querySelector("form").dispatchEvent(event), false);
    assert.equal(document.getElementById("submit-count").textContent, "1");
    const shadow = document.getElementById("shadow-host").shadowRoot;
    const shadowEvent = new window.Event("submit", { bubbles: true, cancelable: true, composed: true });
    assert.equal(shadow.querySelector("form").dispatchEvent(shadowEvent), false);
    assert.equal(document.getElementById("submit-count").textContent, "2", "composed event must not double count");
    assert.deepEqual(errors, []);
  } finally { dom.window.close(); }
});
