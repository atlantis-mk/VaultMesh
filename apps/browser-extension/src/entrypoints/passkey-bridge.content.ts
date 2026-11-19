import { createContentScriptMessageSender } from "@/lib/content-script-messaging";
import { PasskeyBrowserFactory } from "@/lib/passkey-browser-adapter";
import { createPasskeyDialog, parsePasskeyPrompt } from "@/lib/passkey-dialog";
import { PASSKEY_CHANNEL } from "@/lib/passkey-shim";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function parseMessage(data: unknown): { direction: "request" | "abort" | "note"; id: string; reason?: string; operation?: "create" | "get" | "availability"; options?: Record<string, unknown> } | null {
  if (!data || typeof data !== "object") return null;
  const message = data as { channel?: unknown; direction?: unknown; id?: unknown; operation?: unknown; options?: unknown };
  if (message.channel !== PASSKEY_CHANNEL || typeof message.id !== "string" || !UUID.test(message.id)) return null;
  if (message.direction === "abort") return { direction: "abort", id: message.id };
  const reason = (data as { reason?: unknown }).reason;
  if (message.direction === "note") return typeof reason === "string" && /^[A-Za-z0-9:_-]{1,64}$/.test(reason) ? { direction: "note", id: message.id, reason } : null;
  if (
    message.direction === "request"
    && (message.operation === "create" || message.operation === "get" || message.operation === "availability")
    && message.options && typeof message.options === "object" && !Array.isArray(message.options)
  ) return { direction: "request", id: message.id, operation: message.operation, options: message.options as Record<string, unknown> };
  return null;
}

// Isolated world, Chromium only (ADR-0057). It relays page requests to the
// background and never supplies an origin: the background derives it from the
// browser-verified message sender.
export default defineContentScript({
  matches: ["http://*/*", "https://*/*"],
  exclude: ["firefox"],
  allFrames: true,
  matchAboutBlank: true,
  matchOriginAsFallback: true,
  runAt: "document_start",
  main(ctx) {
    const adapter = PasskeyBrowserFactory.create();
    if (!adapter.isSupported) return;
    const targetOrigin = window.location.origin && window.location.origin !== "null" ? window.location.origin : "*";
    const send = createContentScriptMessageSender(
      (message) => browser.runtime.sendMessage(message),
      () => ctx.abort("Extension context invalidated"),
    );
    const post = (message: Record<string, unknown>) => window.postMessage({ channel: PASSKEY_CHANNEL, ...message }, targetOrigin);

    // Only the top frame hosts the dialog; the background targets frame 0 and
    // checks full frame ancestry before serving cross-origin or same-origin requests.
    if (window === window.top) {
      const dialog = createPasskeyDialog(document, {
        choose: (token, choice, remember, itemId) => {
          dialog.hide(token);
          void send({ kind: "vaultmesh.passkey-choice", token, choice, remember, ...(itemId ? { itemId } : {}) });
        },
        openUnlock: () => { void send({ kind: "vaultmesh.open-unlock" }); },
      });
      const onRuntimeMessage = (message: unknown, sender: { id?: string; tab?: unknown }) => {
        if (sender.id !== browser.runtime.id || sender.tab !== undefined || !message || typeof message !== "object") return undefined;
        const command = message as { kind?: unknown; prompt?: unknown; token?: unknown };
        if (command.kind === "vaultmesh.passkey-prompt.show") {
          const prompt = parsePasskeyPrompt(command.prompt);
          if (!prompt) return undefined;
          dialog.show(prompt);
          return Promise.resolve({ status: "shown" as const });
        }
        if (command.kind === "vaultmesh.passkey-prompt.hide" && typeof command.token === "string") {
          dialog.hide(command.token);
          return Promise.resolve({ status: "hidden" as const });
        }
        return undefined;
      };
      browser.runtime.onMessage.addListener(onRuntimeMessage);
      ctx.onInvalidated?.(() => {
        dialog.hide();
        try { browser.runtime.onMessage.removeListener(onRuntimeMessage); } catch { /* runtime gone */ }
      });
    }

    const onWindowMessage = (event: MessageEvent) => {
      if (event.source !== window) return;
      const message = parseMessage(event.data);
      if (!message) return;
      if (message.direction === "abort") {
        void send({ kind: "vaultmesh.passkey.abort", id: message.id });
        return;
      }
      if (message.direction === "note") {
        void send({ kind: "vaultmesh.passkey.note", reason: message.reason });
        return;
      }
      if (window.top !== window && message.operation && !adapter.allowsFrameWebAuthn(document, message.operation)) {
        if (message.operation === "create" || message.operation === "get") {
          void send({ kind: "vaultmesh.passkey.note", reason: "permissions-policy-denied" });
        }
        post({ direction: "response", id: message.id, result: { status: "fallback" } });
        return;
      }
      post({ direction: "ack", id: message.id });
      const optionsJson = JSON.stringify(message.options);
      void send({ kind: "vaultmesh.passkey.request", id: message.id, operation: message.operation, optionsJson })
        .then((result) => post({ direction: "response", id: message.id, result: result ?? { status: "fallback" } }));
    };
    window.addEventListener("message", onWindowMessage);
    ctx.onInvalidated?.(() => window.removeEventListener("message", onWindowMessage));
  },
});
