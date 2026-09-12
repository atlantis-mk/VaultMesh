import { z } from "zod";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { UriMatchStrategy } from "@bitwarden/common/models/domain/domain-service";
import { InlineMenuFillTypes } from "../autofill/enums/autofill-overlay.enum";
import { AutofillScriptGenerator } from "../autofill/services/autofill-script-generator";
import { InlineMenuFieldQualificationService } from "../autofill/services/inline-menu-field-qualification.service";
import { GeneratedValueSchema } from "./vendor/browser-generated-value";
import { fillableLoginInput, excludedMetadata, FILL_CHECK } from "./native-fill-contracts";
import { sendSessionMessage } from "./runtime";
import type { VaultMeshNativeFillContent, CaptureField } from "./native-fill-content";

export const GeneratedInsertSchema = z.object({ kind: z.literal("vaultmesh.native-fill.generated"), requestId: z.string().uuid(), url: z.string().url(), expiresAt: z.string().datetime(), generated: GeneratedValueSchema }).strict();
const qualifier = new InlineMenuFieldQualificationService(true);

/** No values retained: focus remembers only the actual input node and its short-lived URL binding. */
export class NativeGeneratedContent {
  private focus?: { element: HTMLInputElement; url: string; expires: number; form: HTMLFormElement | null; parent: Node | null; semantics: string };
  private remember(element: HTMLInputElement): void {
    this.focus = { element, url: location.href, expires: Date.now() + 60000, form: element.form, parent: element.parentNode,
      semantics: [element.type, element.name, element.id, element.autocomplete].join("\u0000") };
  }
  private readonly seen = new Map<string, number>();
  constructor(private readonly content: VaultMeshNativeFillContent) {}
  start(): void {
    document.addEventListener("focusin", (event) => {
      const target = event.composedPath()[0];
      if (event.isTrusted && target instanceof HTMLInputElement && !target.disabled && !target.readOnly) this.remember(target);
    }, true);
    window.addEventListener("pagehide", () => { this.focus = undefined; });
    chrome.runtime.onMessage.addListener((message, sender, respond) => {
      if (sender.id !== chrome.runtime.id || sender.tab || message?.kind !== "vaultmesh.native-fill.generated") return false;
      void this.insert(message).then(respond, () => respond(null)); return true;
    });
  }
  async insert(raw: unknown): Promise<{ filled: number } | null> {
    const parsed = GeneratedInsertSchema.safeParse(raw);
    let fields: CaptureField[] = [];
    let request: z.infer<typeof GeneratedInsertSchema> | undefined;
    try {
      if (!parsed.success) return null;
      request = parsed.data;
      const focus = this.focus; this.focus = undefined;
      const now = Date.now(); for (const [id, expires] of this.seen) if (expires <= now) this.seen.delete(id);
      if (!focus || focus.element.form !== focus.form || focus.element.parentNode !== focus.parent
        || [focus.element.type, focus.element.name, focus.element.id, focus.element.autocomplete].join("\u0000") !== focus.semantics
        || focus.url !== location.href || focus.expires <= now || request.url !== location.href || this.seen.has(request.requestId) || this.seen.size >= 64
        || Date.parse(request.expiresAt) <= now || Date.parse(request.expiresAt) > now + 30000) return null;
      this.seen.set(request.requestId, Date.parse(request.expiresAt));
      const generation = this.content.currentGeneration();
      const current = async () => request!.url === location.href && Date.parse(request!.expiresAt) > Date.now() && generation === this.content.currentGeneration()
        && await sendSessionMessage({ kind: FILL_CHECK, requestId: request!.requestId }) === true && generation === this.content.currentGeneration();
      if (!await current()) return null;
      fields = await this.content.captureFields();
      const target = fields.find((f) => f.element === focus.element);
      if (!target) return null;
      const password = request.generated.mode === "password" || request.generated.mode === "passphrase";
      if (password ? !qualifier.isNewPasswordField(target.field) : !fillableLoginInput(target.element)
        || request.generated.mode === "username" && (!qualifier.isUsernameField(target.field) || qualifier.isTotpField(target.field))
        || request.generated.mode === "uuid" && target.element.type !== "text") return null;
      const targets = password ? fields.filter((f) => f.scope === target.scope && qualifier.isNewPasswordField(f.field)) : [target];
      if (!targets.length || targets.length > 3 || targets.some((f) => f.element.value || !this.content.captureFieldCurrent(f)
        || excludedMetadata([f.element.id, f.element.name, f.element.placeholder].join(" "))
        || f.element.maxLength >= 0 && request!.generated.value.length > f.element.maxLength)) return null;
      const cipher = new CipherView(); cipher.login.password = password ? "generated" : null; cipher.login.username = password ? null : "generated";
      const page = { url: location.href, documentUrl: location.href, title: "", collectedTimestamp: Date.now(), forms: {}, fields: targets.map((f) => ({ ...f.field, value: "" })) };
      const script = await new AutofillScriptGenerator().generateFillScript(page, { cipher, tabUrl: location.href, defaultUriMatch: UriMatchStrategy.Domain,
        skipUsernameOnlyFill: false, onlyEmptyFields: true, fillNewPassword: password, inlineMenuFillType: password ? InlineMenuFillTypes.PasswordGeneration : undefined,
        remoteTotpPlanning: true, allowTotpAutofill: false, canAccessTotp: false, autoSubmitLogin: false });
      const actions = request.generated.mode === "uuid" ? [["fill_by_opid", target.field.opid, "generated"]] : script?.script ?? [];
      if (actions.filter(([action]) => action === "fill_by_opid").length !== targets.length
        || actions.some(([action, opid, value]) => !["fill_by_opid", "click_on_opid", "focus_by_opid"].includes(action) || !targets.some((f) => f.field.opid === opid) || action === "fill_by_opid" && value !== "generated")) return null;
      return await this.content.executeGenerated(targets, actions, request.generated.value, current, password);
    } finally {
      fields = [];
      if (request) request.generated.value = "";
      if (raw && typeof raw === "object" && "generated" in raw && raw.generated && typeof raw.generated === "object" && "value" in raw.generated) raw.generated.value = "";
    }
  }
}
