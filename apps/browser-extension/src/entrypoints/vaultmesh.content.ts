import { applyAssignments, discardFieldHandles, discoverFields, documentHttpOrigin, type SupportedControl } from "@/lib/form-discovery";
import { startAutofillPage } from "@/lib/autofill-page";
import { createContentScriptMessageSender, registerContentScriptMessageListener } from "@/lib/content-script-messaging";
import { detectPageInformationWithQr, scanTotpQrCodes } from "@/lib/page-information-capture";
import { ContentMessageSchema, SaveCaptureReadyMessageSchema, type AutofillTarget, type ContentMessage } from "@/lib/protocol";
import { createUuid } from "@/lib/uuid";
import { AutofillTargets } from "@/lib/autofill-targets";

export default defineContentScript({
  matches: ["http://*/*", "https://*/*"],
  allFrames: true,
  matchAboutBlank: true,
  matchOriginAsFallback: true,
  runAt: "document_idle",
  main(ctx) {
    let documentId = createUuid();
    let pageUrl = document.location.href;
    const frameOrigin = documentHttpOrigin(document);
    let fields = new Map<string, SupportedControl>();
    // Each discovery keeps its own handle set, keyed by its requestId. A
    // long-lived request (a paired-phone choice can wait up to a minute) must
    // not lose its handles because another fill discovered the page meanwhile.
    const discoveries = new Map<string, Map<string, SupportedControl>>();
    const MAX_PENDING_DISCOVERIES = 16;
    const discardDiscoveries = () => {
      discardFieldHandles(fields);
      for (const handles of discoveries.values()) discardFieldHandles(handles);
      discoveries.clear();
    };
    const targets = new AutofillTargets();
    const fieldTargets = new WeakMap<Map<string, SupportedControl>, AutofillTarget>();
    const sendMessage = createContentScriptMessageSender(
      (message) => browser.runtime.sendMessage(message),
      () => ctx.abort("Extension context invalidated"),
    );
    const autofillPage = startAutofillPage(document, () => documentId, sendMessage, (target) => targets.capture(target, documentId));

    const invalidateDocument = () => {
      documentId = createUuid();
      pageUrl = document.location.href;
      discardDiscoveries();
      targets.clear();
      autofillPage.invalidatePageContext();
    };
    const checkDocument = () => {
      if (document.location.href !== pageUrl) invalidateDocument();
      return documentId;
    };
    const onPageHide = () => { documentId = createUuid(); discardDiscoveries(); targets.clear(); };
    window.addEventListener("popstate", checkDocument);
    window.addEventListener("hashchange", checkDocument);
    window.addEventListener("pagehide", onPageHide);

    const onMessage = (message: unknown) => {
      checkDocument();
      const readyPrompt = SaveCaptureReadyMessageSchema.safeParse(message);
      if (readyPrompt.success) {
        return { status: autofillPage.showPendingCapture(readyPrompt.data.prompt) ? "shown" as const : "ignored" as const };
      }
      const parsed = ContentMessageSchema.safeParse(message);
      if (!parsed.success) {
        return undefined;
      }
      if (parsed.data.kind === "vaultmesh.autofill-rescan") {
        invalidateDocument();
        return { status: "rescanning" };
      }
      if (parsed.data.kind === "vaultmesh.detect-page-information") {
        const pageUrl = document.defaultView?.location.href ?? "";
        if (!isHttpPage(pageUrl)) return { status: "unsupported-page" as const };
        return detectPageInformationWithQr(document, pageUrl).then((detected) => detected
          ? { status: "detected" as const, captureId: createUuid(), ...detected }
          : { status: "empty" as const, pageUrl });
      }
      if (parsed.data.kind === "vaultmesh.scan-totp-qr") {
        const pageUrl = document.defaultView?.location.href ?? "";
        if (!isHttpPage(pageUrl)) return { status: "unsupported-page" as const };
        return scanTotpQrCodes(document).then((values) => values.length
          ? { status: "found" as const, values }
          : { status: "empty" as const });
      }
      if (parsed.data.kind === "vaultmesh.save-page-information") {
        const pageUrl = document.defaultView?.location.href ?? "";
        if (!sameHttpOrigin(parsed.data.pageUrl, pageUrl)) return { status: "unsupported-page" as const };
        return sendMessage({
          kind: "vaultmesh.save-capture-confirmed",
          captureId: parsed.data.captureId,
          pageUrl: parsed.data.pageUrl,
          pageContext: "unknown",
          data: parsed.data.data,
        });
      }
      if (parsed.data.kind !== "vaultmesh.discover-fields" && parsed.data.kind !== "vaultmesh.apply-assignments") {
        return undefined;
      }

      const requestDocumentId = documentId;
      const requestFields = parsed.data.kind === "vaultmesh.apply-assignments"
        ? discoveries.get(parsed.data.requestId) ?? fields
        : fields;
      const requestTarget = fieldTargets.get(requestFields);
      const checkAssignmentScope = () => {
        const current = checkDocument();
        if (!requestTarget) return current;
        const scope = targets.resolve(requestTarget, current);
        return scope && [...requestFields.values()].every((control) => scope.has(control)) ? current : "";
      };
      // Consume the handle set before the first await. A replay must not join
      // an in-flight fill, and its completion must not erase a newer discovery.
      if (parsed.data.kind === "vaultmesh.apply-assignments") {
        discoveries.delete(parsed.data.requestId);
        if (requestFields === fields) fields = new Map();
      }
      return handleMessage(parsed.data, requestDocumentId, requestFields, frameOrigin, checkAssignmentScope, targets).then(async (result) => {
        if (parsed.data.kind === "vaultmesh.discover-fields") {
          if (parsed.data.target) fieldTargets.set(result.fields, parsed.data.target);
          if (requestDocumentId === documentId) {
            fields = result.fields;
            discoveries.delete(parsed.data.requestId);
            discoveries.set(parsed.data.requestId, result.fields);
            for (const stale of discoveries.keys()) {
              if (discoveries.size <= MAX_PENDING_DISCOVERIES) break;
              discoveries.delete(stale);
            }
          }
          return result.response;
        }

        if (parsed.data.kind === "vaultmesh.apply-assignments" && parsed.data.selectedItem && "results" in result.response && result.response.status === "completed") {
          const filledHandles = new Set(result.response.results
            .filter((entry) => entry.status === "filled")
            .map((entry) => entry.handle));
          const assignedControls = parsed.data.assignments
            .filter((assignment) => filledHandles.has(assignment.handle))
            .map((assignment) => requestFields.get(assignment.handle))
            .filter((control): control is SupportedControl => Boolean(control));
          if (assignedControls.length > 0) {
            autofillPage.recordFilledItem(parsed.data.selectedItem, assignedControls);
            await autofillPage.completePasswordChange(parsed.data.selectedItem, assignedControls);
          }
        }

        requestFields.clear();
        return result.response;
      });
    };
    ctx.onInvalidated(() => {
      documentId = createUuid();
      autofillPage.dispose();
      discardDiscoveries();
      targets.clear();
      window.removeEventListener("popstate", checkDocument);
      window.removeEventListener("hashchange", checkDocument);
      window.removeEventListener("pagehide", onPageHide);
      try {
        browser.runtime.onMessage.removeListener(onMessage);
      } catch {
        // The runtime API itself is unavailable after an extension reload.
      }
    });
    registerContentScriptMessageListener(
      (listener) => browser.runtime.onMessage.addListener(listener),
      onMessage,
      () => ctx.abort("Extension context invalidated"),
    );
  },
});

async function handleMessage(
  message: Extract<ContentMessage, { kind: "vaultmesh.discover-fields" | "vaultmesh.apply-assignments" }>,
  documentId: string,
  fields: Map<string, SupportedControl>,
  frameOrigin: string,
  currentDocumentId: () => string,
  targets: AutofillTargets,
) {
  if (message.kind === "vaultmesh.discover-fields") {
    const scope = message.target ? targets.resolve(message.target, documentId) : undefined;
    const discovered = discoverFields(document);
    if (scope !== undefined) {
      for (const [handle, control] of discovered.handles) if (!scope?.has(control)) discovered.handles.delete(handle);
      discovered.descriptors = discovered.descriptors.filter((field) => discovered.handles.has(field.handle));
    }
    return {
      fields: discovered.handles,
      response: {
        documentId,
        frameOrigin,
        fields: discovered.descriptors,
      },
    };
  }

  return {
    fields,
    response: await applyAssignments({
      message,
      documentId,
      fields,
      currentOrigin: frameOrigin,
      currentDocumentId,
    }),
  };
}

function isHttpPage(pageUrl: string): boolean {
  try { return ["http:", "https:"].includes(new URL(pageUrl).protocol); } catch { return false; }
}

function sameHttpOrigin(expectedUrl: string, currentUrl: string): boolean {
  try {
    const expected = new URL(expectedUrl);
    const current = new URL(currentUrl);
    return ["http:", "https:"].includes(current.protocol) && expected.origin === current.origin;
  } catch {
    return false;
  }
}
