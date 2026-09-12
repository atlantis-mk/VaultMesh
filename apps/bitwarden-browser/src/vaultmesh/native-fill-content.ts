import { z } from "zod";
import { CollectAutofillContentService } from "../autofill/services/collect-autofill-content.service";
import DomElementVisibilityService from "../autofill/services/dom-element-visibility.service";
import { DomQueryService } from "../autofill/services/dom-query.service";
import InsertAutofillContentService from "../autofill/services/insert-autofill-content.service";
import { InlineMenuFieldQualificationService } from "../autofill/services/inline-menu-field-qualification.service";
import { AutofillOverlayContentService } from "../autofill/services/autofill-overlay-content.service";
import AutofillScript from "../autofill/models/autofill-script";
import type AutofillField from "../autofill/models/autofill-field";
import type { FormFieldElement } from "../autofill/types";
import { createVaultMeshUuid } from "./uuid";
import { sendSessionMessage } from "./runtime";
import { NativePasswordMaintenance } from "./native-password-maintenance";
import { NativeItemSourceSchema } from "./vendor/browser-native-item-plan";
import { formatNativeItem, planNativeItem, credentialCustomSources } from "./native-item-planner";
import { fillableControl, isFillControl, type FillControl } from "./native-fill-contracts";
import { AssignmentSchema, EmailAssignmentSchema, CollectedPageSchema, FILL_APPLY, FILL_CANCEL, FILL_CHECK, FILL_COLLECT,
  FILL_LIFETIME, clearAssignment, fillableLoginInput, projectField, nativePage, type CollectedPage } from "./native-fill-contracts";

export const PlannedScriptSchema = z.array(z.tuple([
  z.enum(["click_on_opid", "focus_by_opid", "fill_by_opid"]), z.string().max(128),
  z.union([z.string().regex(/^(?:username|password|012345|[0-5]|email-otp|custom:[0-9]{1,3})$/), NativeItemSourceSchema]).nullable(),
])).max(1_201);
type Binding = { element: FillControl; form: HTMLFormElement | null; parent: Node | null; semantics: string };
type Pending = { page: CollectedPage; bindings: Map<string, Binding>; generation: number; topOrigin: string; target?: LocalTarget; maintenanceFields: CaptureField[]; automatic: boolean };
type LocalTarget = Binding & { scope: HTMLElement; url: string; expires: number; context: "login" | "otp" | "card" | "identity" | "ssh" | "secret"; automatic: boolean };
export type CaptureControl = Binding & { field: AutofillField; scope: HTMLElement };
export type CaptureField = CaptureControl & { element: HTMLInputElement };
const semantics = (element: FillControl) => [element.type, element.id, element.name, element.autocomplete,
  element.title, element.getAttribute("placeholder"), element.getAttribute("aria-label"),
  element instanceof HTMLSelectElement ? JSON.stringify([...element.options].map((o) => [o.text, o.value, o.disabled])) : ""].join("\u0000");

/** Thin lifetime/assignment boundary around the actual upstream collector and executor. */
export class VaultMeshNativeFillContent {
  private readonly generated = new WeakSet<HTMLInputElement>();
  currentGeneration(): number { return this.generation; }
  isCollecting(): boolean { return this.busy; }
  private readonly maintenance = new NativePasswordMaintenance();
  wasGenerated(element: HTMLInputElement): boolean { return this.generated.has(element) || this.maintenance.wasGenerated(element); }

  async executeGenerated(targets: CaptureField[], actions: (string | null)[][], value: string, current: () => Promise<boolean>, password: boolean) {
    if (this.busy) return null;
    this.busy = true;
    const written = new Set<Element>(); const fill = new AutofillScript();
    const guard = (element: Element) => targets.some((f) => f.element === element) && targets.every((f) => this.captureFieldCurrent(f)
      && (written.has(f.element) ? f.element.value === value : !f.element.value));
    const executor = new InsertAutofillContentService(this.visibility, this.collector, guard,
      (element) => { written.add(element); if (password && element instanceof HTMLInputElement) this.generated.add(element); }, current);
    try {
      for (const [action, opid] of actions) {
        if (!opid || !["fill_by_opid", "click_on_opid", "focus_by_opid"].includes(action ?? "")) return null;
        fill.script.push(action === "fill_by_opid" ? [action, opid, value] : [action as "click_on_opid" | "focus_by_opid", opid]);
      }
      fill.autosubmit = null; fill.savedUrls = []; fill.untrustedIframe = false;
      if (!await current()) return null;
      await executor.fillForm(fill, false);
      return { filled: written.size };
    } finally { value = ""; for (const action of fill.script) if (action.length > 2) action[2] = ""; fill.script.length = 0; this.busy = false; }
  }
  private readonly visibility = new DomElementVisibilityService();
  private readonly domQuery = new DomQueryService();
  private readonly ownedHosts = new WeakSet<Element>();
  private readonly collector = new CollectAutofillContentService(this.visibility, this.domQuery, undefined, true);
  private readonly qualification = new InlineMenuFieldQualificationService(true);
  private readonly ownership = new AutofillOverlayContentService(new DomQueryService(), this.visibility, this.qualification);
  private readonly targets = new Map<string, LocalTarget>();
  private newPasswordElements = new Set<Element>();
  private pending?: Pending;
  private active?: Pending;
  private generation = 0;
  private documentId = createVaultMeshUuid();
  private timer?: ReturnType<typeof setTimeout>;
  private busy = false;
  private captureRequest?: Promise<CaptureControl[]>;
  private clearActiveValues?: () => void;
  private overwrites = new Set<string>();
  private written = new Set<Element>();
  private readonly executor = new InsertAutofillContentService(this.visibility, this.collector,
    (element) => this.guard(element), (element) => this.written.add(element),
    async () => {
      const active = this.active;
      if (!active || !this.current(active)) return false;
      try {
        const result = await sendSessionMessage({ kind: FILL_CHECK, requestId: active.page.requestId });
        return result === true && this.current(active);
      } catch { return false; }
    });

  constructor() {
    this.domQuery.setOwnedShadowHostPredicate((host) => this.ownedHosts.has(host));
  }

  ownHost(host: Element): void { this.ownedHosts.add(host); }

  start(): void {
    chrome.runtime.onMessage.addListener((message, sender, respond) => {
      if (sender.id !== chrome.runtime.id || sender.tab) return false;
      if (![FILL_COLLECT, FILL_APPLY, FILL_CANCEL].includes(message?.kind)) return false;
      if (message.kind === FILL_CANCEL) { this.invalidate(); respond(null); return false; }
      const work = message.kind === FILL_COLLECT ? this.collect(message.requestId, message.targetRef, message.automatic === true, message.topOrigin, message.expectedUsername) : this.apply(message);
      void work.then(respond, () => respond(null));
      return true;
    });
    for (const event of ["pagehide", "popstate", "hashchange"]) globalThis.addEventListener(event, () => this.invalidate());
  }

  invalidate(keepTargets = false): void {
    this.clearActiveValues?.();
    this.generation++;
    this.documentId = createVaultMeshUuid();
    this.pending = undefined;
    this.active = undefined;
    this.overwrites.clear();
    if (this.timer) clearTimeout(this.timer);
    this.collector.stopMonitoring();
    if (!keepTargets) this.targets.clear();
    this.newPasswordElements.clear();
  }

  async collect(requestId: unknown, targetRef?: unknown, automatic = false, topOrigin: unknown = location.origin, expectedUsername?: unknown): Promise<CollectedPage | null> {
    if (this.busy || !z.string().uuid().safeParse(requestId).success || !/^https?:$/.test(location.protocol)) return null;
    if (typeof topOrigin !== "string" || !/^https?:\/\//.test(topOrigin) || new URL(topOrigin).origin !== topOrigin || (automatic && topOrigin !== location.origin)) return null;
    const target = targetRef === undefined ? undefined : typeof targetRef === "string" ? this.targets.get(targetRef) : undefined;
    if ((targetRef !== undefined && (!target || !this.validTarget(target))) || (automatic && !target?.automatic)) return null;
    if (typeof targetRef === "string") this.targets.delete(targetRef);
    this.invalidate(true);
    this.busy = true;
    const generation = this.generation;
    const url = location.href;
    try {
      this.collector.startMonitoring();
      this.domQuery.refreshShadowDomStateForUserRequest();
      this.collector.prepareForExplicitCollection();
      const details = await this.collector.getPageDetails();
      if (generation !== this.generation || url !== location.href) return null;
      if (target && !this.validTarget(target)) return null;
      for (const field of details.fields) {
        const element = this.collector.getAutofillFieldElementByOpid(field.opid);
        if (element && this.qualification.isNewPasswordField(field)) this.newPasswordElements.add(element);
      }
      if (automatic && target && [...this.newPasswordElements].some((element) => this.belongs(element, target))) return null;
      if (automatic && target) {
        if (typeof expectedUsername !== "string" || expectedUsername.length > 2048) return null;
        for (const field of details.fields) {
          const element = this.collector.getAutofillFieldElementByOpid(field.opid);
          if (element instanceof HTMLInputElement && this.belongs(element, target) && element.value
            && this.qualification.isUsernameField(field)
            && element.value.trim().toLocaleLowerCase() !== expectedUsername.trim().toLocaleLowerCase()) return null;
        }
      }
      const bindings = new Map<string, Binding>();
      const fields = details.fields.slice(0, 300).flatMap((field) => {
        const element = this.collector.getAutofillFieldElementByOpid(field.opid);
        if (!isFillControl(element) || !fillableControl(element) || !field.viewable) return [];
        if (target && !this.belongs(element, target)) return [];
        if (automatic && (element.value || credentialCustomSources(field).length || !this.qualification.isFieldForLoginForm(field, details))) return [];
        bindings.set(field.opid, { element, form: element.form, parent: element.parentNode, semantics: semantics(element) });
        const projected = projectField(field, createVaultMeshUuid());
        if (this.qualification.isTotpField(field)) projected.context = "otp";
        else if (automatic) projected.context = "login";
        return [projected];
      });
      const forms = Object.fromEntries(Object.entries(details.forms).slice(0, 300).map(([id, form]) => [id, {
        opid: form.opid, htmlName: form.htmlName ?? "", htmlID: form.htmlID ?? "", htmlAction: form.htmlAction ?? "",
        htmlMethod: form.htmlMethod ?? "", htmlClass: form.htmlClass ?? "", htmlAncestorHeadings: (form.htmlAncestorHeadings ?? []).slice(0, 20),
      }]));
      const page = CollectedPageSchema.parse({ requestId, documentId: this.documentId, url,
        expiresAt: new Date(Date.now() + FILL_LIFETIME).toISOString(), fields, forms });
      if (JSON.stringify(page).length > 180_000) return null;
      const maintenanceFields: CaptureField[] = [];
      if (!automatic) for (const field of details.fields.slice(0, 300)) {
        const element = this.collector.getAutofillFieldElementByOpid(field.opid);
        if (!(element instanceof HTMLInputElement) || element.type !== "password" || !field.viewable || (target && !this.belongs(element, target))) continue;
        const scope = await this.ownership.getLocalFormScope(element);
        if (scope) maintenanceFields.push({ element, form: element.form, parent: element.parentNode, semantics: semantics(element), scope, field: { ...field, value: "" } });
      }
      if (generation !== this.generation || url !== location.href) return null;
      this.pending = { page, bindings, generation, target, topOrigin, maintenanceFields, automatic };
      this.timer = setTimeout(() => this.invalidate(), FILL_LIFETIME);
      return page;
    } finally {
      this.busy = false;
      if (!this.pending) this.collector.stopMonitoring();
    }
  }

  private belongs(element: Element, target: LocalTarget): boolean {
    return isFillControl(element) && (target.form ? element.form === target.form : !element.form && target.scope.contains(element));
  }

  private validTarget(target: LocalTarget): boolean {
    return target.expires > Date.now() && target.url === location.href && target.scope.isConnected
      && (["login", "otp"].includes(target.context) || !target.element.value || this.written.has(target.element))
      && target.element.form === target.form && target.element.parentNode === target.parent
      && semantics(target.element) === target.semantics && this.belongs(target.element, target)
      && fillableControl(target.element) && this.visibility.isElementViewableNow(target.element);
  }

  /** Field qualification remains upstream; only DOM ownership and lifetime are adapted. */
  async createTarget(element: FillControl): Promise<{ targetRef: string; context: "login" | "otp" | "card" | "identity" | "ssh" | "secret"; automatic: boolean; scope: HTMLElement } | null> {
    // Startup capture and focus may arrive together. Wait for the existing
    // read-only collection rather than dropping the focused field's icon.
    const generation = this.generation;
    if (this.captureRequest) await this.captureRequest;
    if (generation !== this.generation || !element.isConnected) return null;
    if (this.busy || !fillableControl(element)) return null;
    const page = await this.collect(createVaultMeshUuid());
    if (!page || !this.pending) return null;
    const field = page.fields.find((field) => this.pending?.bindings.get(field.opid)?.element === element);
    if (!field) return null;
    const scope = await this.ownership.getLocalFormScope(element);
    if (!scope || !this.pending || !this.current(this.pending)) return null;
    const target: LocalTarget = { element, form: element.form, parent: element.parentNode, semantics: semantics(element),
      scope, url: location.href, expires: Date.now() + FILL_LIFETIME, context: "login", automatic: false };
    const scopedPage = nativePage({ ...page, fields: page.fields.filter((field) => {
      const node = this.pending?.bindings.get(field.opid)?.element;
      return node && this.belongs(node, target);
    }) });
    const nativeField = scopedPage.fields.find((candidate) => candidate.opid === field.opid)!;
    if (credentialCustomSources(nativeField).length > 1) return null;
    const card = (await planNativeItem(scopedPage, "card")).has(field.opid);
    const identity = (await planNativeItem(scopedPage, "identity")).has(field.opid);
    const ssh = (await planNativeItem(scopedPage, "ssh")).has(field.opid);
    const secret = (await planNativeItem(scopedPage, "secret")).has(field.opid);
    if (!this.pending || !this.current(this.pending) || !this.validTarget(target)) return null;
    if (ssh && secret) return null;
    if (ssh) target.context = "ssh";
    else if (secret) target.context = "secret";
    else if (card) target.context = "card";
    else if (this.qualification.isTotpField(nativeField)) target.context = "otp";
    else if (this.qualification.isFieldForLoginForm(nativeField, scopedPage)) target.context = "login";
    else if (identity) target.context = "identity";
    else return null;
    if (!["login", "otp"].includes(target.context) && !field.empty) return null;
    if (["card", "ssh", "secret"].includes(target.context) && location.protocol !== "https:") return null;
    target.automatic = (target.context === "login" || target.context === "otp") && field.empty && ![...this.newPasswordElements].some((node) => this.belongs(node, target));
    for (const [id, ref] of this.targets) if (!this.validTarget(ref)) this.targets.delete(id);
    if (this.targets.size >= 64) return null;
    const targetRef = createVaultMeshUuid();
    this.targets.set(targetRef, target);
    return { targetRef, context: target.context, automatic: target.automatic, scope };
  }

  targetCurrent(targetRef: string): boolean {
    const target = this.targets.get(targetRef);
    return !!target && this.validTarget(target);
  }

  releaseTarget(targetRef: string): void { this.targets.delete(targetRef); }

  async captureFields(): Promise<CaptureField[]> {
    return (await this.captureControls()).filter((field): field is CaptureField => field.element instanceof HTMLInputElement);
  }

  captureControls(): Promise<CaptureControl[]> {
    // Login and managed capture share one collector read. Otherwise identically
    // scheduled refresh timers can permanently starve the second observer.
    if (this.captureRequest) return this.captureRequest;
    const request = this.readCaptureControls();
    this.captureRequest = request;
    void request.finally(() => { if (this.captureRequest === request) this.captureRequest = undefined; }).catch((): undefined => undefined);
    return request;
  }

  private async readCaptureControls(): Promise<CaptureControl[]> {
    if (this.busy) return [];
    this.busy = true;
    const generation = this.generation;
    try {
      this.collector.startMonitoring();
      this.domQuery.refreshShadowDomStateForUserRequest();
      const details = await this.collector.getPageDetails();
      const result: CaptureControl[] = [];
      for (const field of details.fields.slice(0, 300)) {
        const element = this.collector.getAutofillFieldElementByOpid(field.opid);
        if (!isFillControl(element) || !field.viewable || element.disabled || !element.isConnected) continue;
        const scope = await this.ownership.getLocalFormScope(element);
        if (scope) result.push({ element, form: element.form, parent: element.parentNode, semantics: semantics(element), scope,
          field: { ...field, value: "" } }); // metadata only; read actual values synchronously at submission
      }
      return generation === this.generation ? result : [];
    } finally { this.busy = false; if (!this.pending) this.collector.stopMonitoring(); }
  }

  captureFieldCurrent(binding: CaptureControl): boolean {
    return binding.element.isConnected && binding.element.form === binding.form && binding.element.parentNode === binding.parent
      && semantics(binding.element) === binding.semantics && this.visibility.isElementViewableNow(binding.element)
      && !binding.element.disabled && !("readOnly" in binding.element && binding.element.readOnly) && !binding.element.closest("[inert]");
  }

  async automaticTargets(): Promise<HTMLInputElement[]> {
    const page = await this.collect(createVaultMeshUuid());
    if (!page || !this.pending) return [];
    const details = nativePage(page);
    return page.fields.flatMap((field) => {
      const element = this.pending?.bindings.get(field.opid)?.element;
      const nativeField = details.fields.find((value) => value.opid === field.opid)!;
      return element instanceof HTMLInputElement && field.empty && this.qualification.isFieldForLoginForm(nativeField, details) ? [element] : [];
    }).slice(0, 64);
  }

  async automaticTargetAttempted(element: HTMLInputElement, attempted: WeakSet<HTMLElement>): Promise<boolean> {
    // Resolve ownership before createTarget's full collection. The actual target
    // is still freshly collected/qualified and marked only when an attempt starts.
    const scope = await this.ownership.getLocalFormScope(element);
    return !!scope && attempted.has(scope);
  }

  private current(pending: Pending): boolean {
    return pending.generation === this.generation && pending.page.documentId === this.documentId
      && pending.page.url === location.href && Date.parse(pending.page.expiresAt) > Date.now();
  }

  private guard(element: FormFieldElement): boolean {
    const active = this.active;
    if (!active || !this.current(active) || !isFillControl(element)) return false;
    const field = active.page.fields.find((field) => active.bindings.get(field.opid)?.element === element);
    const binding = field && active.bindings.get(field.opid);
    return !!(field && binding && fillableControl(element) && element.form === binding.form
      && (!active.target || (this.validTarget(active.target) && this.belongs(element, active.target)))
      && element.parentNode === binding.parent && semantics(element) === binding.semantics
      && this.collector.getAutofillFieldElementByOpid(field.opid) === element
      && this.visibility.isElementViewableNow(element)
      && (this.overwrites.has(field.handle) || this.written.has(element) || !element.value));
  }

  async apply(message: { assignment?: unknown; script?: unknown; emailOtp?: unknown }): Promise<{ filled: number } | null> {
    const pending = this.pending;
    if (this.busy || !pending) { clearAssignment(message.assignment); return null; }
    this.pending = undefined; // consume BEFORE any await or write, never replay a failed fill
    this.busy = true;
    let assignment: z.infer<typeof AssignmentSchema> | z.infer<typeof EmailAssignmentSchema> | undefined;
    const fill = new AutofillScript();
    try {
      const email = message.emailOtp === true;
      assignment = (email ? EmailAssignmentSchema : AssignmentSchema).parse(message.assignment);
      const script = PlannedScriptSchema.parse(message.script);
      const frame = assignment.frames[0];
      if (!this.current(pending) || assignment.requestId !== pending.page.requestId
        || frame.documentId !== pending.page.documentId || assignment.expiresAt !== pending.page.expiresAt
        || frame.frameOrigin !== location.origin || assignment.topOrigin !== pending.topOrigin) return null;
      const values = new Map(frame.assignments.map((entry) => [entry.handle, entry]));
      if (values.size !== frame.assignments.length || [...values.keys()].some((handle) => !pending.page.fields.some((f) => f.handle === handle))) return null;
      if (frame.assignments.some((entry) => entry.overwrite && pending.page.fields.find((f) => f.handle === entry.handle)?.empty)) return null;
      const used = new Set<string>();
      for (const [action, opid, source] of script) {
        const field = pending.page.fields.find((f) => f.opid === opid);
        const value = field && values.get(field.handle);
        if (!field || !value || (action === "fill_by_opid" && (!source || used.has(opid)))) return null;
        if (action === "fill_by_opid" && source === "password" && field.type !== "password") return null;
        if (action === "fill_by_opid" && source === "username" && !["text", "email", "tel"].includes(field.type)) return null;
        if (action === "fill_by_opid" && (email !== (source === "email-otp"))) return null;
        if (action === "fill_by_opid" && email && (field.context !== "otp" || !field.empty || value.overwrite
          || !["text", "tel", "number"].includes(field.type) || field.type === "number" && !/^\d+$/.test(value.value)
          || !/^[A-Za-z0-9]{1,8}$/.test(value.value) || field.maxLength != null && field.maxLength > 0 && value.value.length > field.maxLength)) return null;
        if (action === "fill_by_opid" && /^(?:012345|[0-5])$/.test(source ?? "")
          && (!field.empty || value.overwrite || !["text", "tel", "number"].includes(field.type)
            || (source?.length === 1 && field.maxLength !== 1))) return null;
        if (action === "fill_by_opid") used.add(opid);
        if (action === "fill_by_opid" && NativeItemSourceSchema.safeParse(source).success) {
          if (email || !source?.startsWith(`${AssignmentSchema.parse(assignment).selectedItem.kind}:`) || !field.empty || value.overwrite) return null;
          const formatted = await formatNativeItem(nativePage(pending.page), opid, NativeItemSourceSchema.parse(source), value.value);
          if (!this.current(pending)) return null;
          if (formatted != null && !(field.maxLength != null && field.maxLength > 0 && formatted.length > field.maxLength)) fill.script.push([action, opid, formatted]);
        } else fill.script.push(action === "fill_by_opid" ? [action, opid, value.value] : [action, opid]);
      }
      if (used.size !== values.size) return null;
      this.active = pending;
      this.overwrites = new Set(frame.assignments.filter((a) => a.overwrite).map((a) => a.handle));
      this.written.clear();
      fill.savedUrls = []; // background rejects HTTPS -> HTTP before disclosure
      fill.autosubmit = null;
      fill.untrustedIframe = false; // browser-verified target; cross-origin requires explicit popup confirmation
      this.clearActiveValues = () => {
        clearAssignment(assignment);
        clearAssignment(message.assignment);
        fill.script.forEach((action) => { if (action.length > 2) action[2] = ""; });
        fill.script.length = 0;
      };
      await this.executor.fillForm(fill, false);
      if (!pending.automatic && this.current(pending)) {
        const passwords = new Set(script.filter(([action, , source]) => action === "fill_by_opid" && source === "password")
          .map(([, opid]) => pending.bindings.get(opid)?.element).filter((element): element is HTMLInputElement => element instanceof HTMLInputElement && this.written.has(element)));
        await this.maintenance.fill(pending.maintenanceFields, passwords, this.collector, this.visibility,
          async () => this.current(pending) && await sendSessionMessage({ kind: FILL_CHECK, requestId: pending.page.requestId }) === true && this.current(pending),
          (field) => this.captureFieldCurrent(field) && (!pending.target || this.validTarget(pending.target)));
      }
      return { filled: this.written.size };
    } finally {
      clearAssignment(assignment);
      clearAssignment(message.assignment);
      fill.script.forEach((action) => { if (action.length > 2) action[2] = ""; });
      fill.script.length = 0;
      this.clearActiveValues = undefined;
      this.busy = false;
      this.written.clear();
      this.invalidate();
    }
  }
}
