import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { LoginView } from "@bitwarden/common/vault/models/view/login.view";
import { CipherType } from "@bitwarden/common/vault/enums";
import { UriMatchStrategy } from "@bitwarden/common/models/domain/domain-service";
import { AutofillScriptGenerator } from "../autofill/services/autofill-script-generator";
import { InlineMenuFillTypes } from "../autofill/enums/autofill-overlay.enum";
import type { CollectAutofillContentService } from "../autofill/services/collect-autofill-content.service";
import type DomElementVisibilityService from "../autofill/services/dom-element-visibility.service";
import InsertAutofillContentService from "../autofill/services/insert-autofill-content.service";
import type { CaptureField } from "./native-fill-content";
import { excludedMetadata } from "./native-fill-contracts";
import { generateMaintenancePassword } from "./password-generator";
import { loadGeneratorPreferences } from "./generator-preferences";

/** Generated values stay in this frame; native roles, script planner and executor are reused. */
export class NativePasswordMaintenance {
  private readonly generated = new WeakSet<HTMLInputElement>();
  private readonly attempted = new WeakSet<HTMLElement>();
  wasGenerated(element: HTMLInputElement): boolean { return this.generated.has(element); }

  async fill(fields: CaptureField[], writtenPasswords: Set<Element>, collector: CollectAutofillContentService,
    visibility: DomElementVisibilityService, current: () => Promise<boolean>, bindingCurrent: (field: CaptureField) => boolean): Promise<void> {
    const currents = fields.filter((field) => writtenPasswords.has(field.element)
      && field.element.type === "password" && /(?:^|\s)current-password(?:\s|$)/.test(field.field.autoCompleteType));
    if (!currents.length) return;
    const options = (await loadGeneratorPreferences()).password;
    if (!await current()) return;
    for (const currentPassword of currents) {
      const scope = currentPassword.scope;
      if (this.attempted.has(scope) || !bindingCurrent(currentPassword)) continue;
      const next = fields.filter((field) => field.scope === scope && field.element.type === "password"
        && /(?:^|\s)new-password(?:\s|$)/.test(field.field.autoCompleteType));
      // A reliable change-password cluster has one current password and a new/confirmation pair.
      if (currents.filter((field) => field.scope === scope).length !== 1 || next.length < 2 || next.length > 3
        || next.some((field) => field.element.value || !bindingCurrent(field)
          || (field.element.maxLength >= 0 && field.element.maxLength < options.length)
          || excludedMetadata([field.element.name, field.element.id, field.element.placeholder, field.element.getAttribute("aria-label") ?? ""].join(" ")))) continue;
      this.attempted.add(scope); // one attempt, including failure; never regenerate on retries
      let password = "";
      let script: Awaited<ReturnType<AutofillScriptGenerator["generateFillScript"]>>;
      const written = new Set<Element>();
      const cipher = new CipherView(); cipher.type = CipherType.Login; cipher.login = new LoginView();
      cipher.login.password = "generated-password-marker";
      try {
        if (!await current()) return;
        password = await generateMaintenancePassword(options);
        script = await new AutofillScriptGenerator().generateFillScript({
          url: location.href, documentUrl: location.href, title: "", collectedTimestamp: Date.now(),
          fields: next.map((entry) => ({ ...entry.field, value: "" })), forms: {},
        }, { cipher, tabUrl: location.href, defaultUriMatch: UriMatchStrategy.Domain,
          skipUsernameOnlyFill: true, onlyEmptyFields: true, fillNewPassword: true, inlineMenuFillType: InlineMenuFillTypes.PasswordGeneration,
          remoteTotpPlanning: true, allowTotpAutofill: false, canAccessTotp: false, autoSubmitLogin: false });
        if (!script || script.script.filter(([action]) => action === "fill_by_opid").length !== next.length) continue;
        for (const action of script.script) {
          if (!["click_on_opid", "focus_by_opid", "fill_by_opid"].includes(action[0]) || !next.some((entry) => entry.field.opid === action[1])) return;
          if (action[0] === "fill_by_opid") {
            if (action[2] !== "generated-password-marker") return;
            action[2] = password;
          }
        }
        const guard = (element: Element) => next.some((entry) => entry.element === element)
          && bindingCurrent(currentPassword) && next.every((entry) => bindingCurrent(entry)
            && (written.has(entry.element) ? entry.element.value === password : !entry.element.value));
        const executor = new InsertAutofillContentService(visibility, collector, guard,
          (element) => { written.add(element); if (element instanceof HTMLInputElement) this.generated.add(element); }, current);
        script.autosubmit = null; script.untrustedIframe = false;
        if (await current()) await executor.fillForm(script, false);
      } catch {
        // Credential assignment has already completed. A secondary generation failure
        // must not hide those writes or encourage another fill; this scope is consumed.
        return;
      } finally {
        password = ""; cipher.login.password = null;
        script?.script.forEach((action) => { if (action.length > 2) action[2] = ""; });
        if (script) script.script.length = 0;
      }
    }
  }
}
