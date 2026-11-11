import { createContentScriptMessageSender } from "@/lib/content-script-messaging";
import { createPasskeyDialog, type PasskeyPromptView } from "@/lib/passkey-dialog";
import { PASSKEY_CHANNEL } from "@/lib/passkey-shim";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Hand-rolled validation keeps this document_start script free of heavy dependencies.
function parsePrompt(value: unknown): PasskeyPromptView | null {
  if (!value || typeof value !== "object") return null;
  const prompt = value as { token?: unknown; operation?: unknown; origin?: unknown; stage?: unknown };
  if (typeof prompt.token !== "string" || !UUID.test(prompt.token)) return null;
  if (prompt.operation !== "create" && prompt.operation !== "get") return null;
  if (prompt.stage !== "choose" && prompt.stage !== "unlock") return null;
  return { token: prompt.token, operation: prompt.operation, origin: typeof prompt.origin === "string" ? prompt.origin.slice(0, 256) : null, stage: prompt.stage };
}

function parseMessage(data: unknown): { direction: "request" | "abort"; id: string; operation?: "create" | "get" | "availability"; options?: Record<string, unknown> } | null {
  if (!data || typeof data !== "object") return null;
  const message = data as { channel?: unknown; direction?: unknown; id?: unknown; operation?: unknown; options?: unknown };
  if (message.channel !== PASSKEY_CHANNEL || typeof message.id !== "string" || !UUID.test(message.id)) return null;
  if (message.direction === "abort") return { direction: "abort", id: message.id };
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
    const targetOrigin = window.location.origin && window.location.origin !== "null" ? window.location.origin : "*";
    const send = createContentScriptMessageSender(
      (message) => browser.runtime.sendMessage(message),
      () => ctx.abort("Extension context invalidated"),
    );
    const post = (message: Record<string, unknown>) => window.postMessage({ channel: PASSKEY_CHANNEL, ...message }, targetOrigin);

    // Only the top frame hosts the dialog; the background targets frame 0, and
    // only same-origin request chains are ever served, so it never crosses origins.
    if (window === window.top) {
      const dialog = createPasskeyDialog(document, {
        choose: (token, choice, remember) => {
          dialog.hide(token);
          void send({ kind: "vaultmesh.passkey-choice", token, choice, remember });
        },
        openUnlock: () => { void send({ kind: "vaultmesh.open-unlock" }); },
      });
      browser.runtime.onMessage.addListener((message: unknown, sender: { id?: string; tab?: unknown }) => {
        if (sender.id !== browser.runtime.id || sender.tab !== undefined || !message || typeof message !== "object") return undefined;
        const command = message as { kind?: unknown; prompt?: unknown; token?: unknown };
        if (command.kind === "vaultmesh.passkey-prompt.show") {
          const prompt = parsePrompt(command.prompt);
          if (!prompt) return undefined;
          dialog.show(prompt);
          return Promise.resolve({ status: "shown" as const });
        }
        if (command.kind === "vaultmesh.passkey-prompt.hide" && typeof command.token === "string") {
          dialog.hide(command.token);
          return Promise.resolve({ status: "hidden" as const });
        }
        return undefined;
      });
    }

    window.addEventListener("message", (event) => {
      if (event.source !== window) return;
      const message = parseMessage(event.data);
      if (!message) return;
      if (message.direction === "abort") {
        void send({ kind: "vaultmesh.passkey.abort", id: message.id });
        return;
      }
      post({ direction: "ack", id: message.id });
      const optionsJson = JSON.stringify(message.options);
      void send({ kind: "vaultmesh.passkey.request", id: message.id, operation: message.operation, optionsJson })
        .then((result) => post({ direction: "response", id: message.id, result: result ?? { status: "fallback" } }));
    });
  },
});
