import { openDeviceAssist } from "@/lib/device-assist-overlay";
import { deviceAssistKindForControl } from "@/lib/form-discovery";
import { VAULTMESH_UI_SELECTOR, accessibleShadowRoot, analyzeControlSemantics, credentialFieldRole, discoverFields, classifyControl, formControls, semanticCluster, hasLoginFields, isEmailAccountControl, isNewPasswordControl, loginFormSignature, passwordFieldGroup, selectAutofillPageContext, shouldPreserveExistingLoginAccount, withFieldDiscoveryCache } from "@/lib/form-discovery";
import { InlineAutofillMenu } from "@/lib/inline-autofill";
import { InlineAutofillTrigger } from "@/lib/inline-autofill-trigger";
import { fillResultStatus, filterCandidatesByTypedUsername, inlineFillFailureMessage } from "@/lib/autofill-selection";
import { fillGeneratedLogin, fillGeneratedPassword } from "@/lib/generated-login-fill";
import { generatePassword } from "@/lib/generated-credentials";
import { AutofillAvailabilityResponseSchema, AutofillCandidatesResponseSchema, SaveCaptureDecisionResponseSchema, SaveCapturePendingResponseSchema, SaveCaptureQueuedResponseSchema, type AutofillCandidate, type InlineAutofillCandidate } from "@/lib/protocol";
import { loadPasswordGeneratorOptions, loadUsernameGeneratorOptions } from "@/lib/generator-preferences";
import { captureSubmittedData, capturedDataSignature, hasCapturedData, submittedDataContext, type CapturedSaveData } from "@/lib/save-capture";
import { SaveCapturePrompt } from "@/lib/save-capture-prompt";
import { createUuid } from "@/lib/uuid";
import type { AutofillTarget } from "@/lib/protocol";
import { ShadowHostTracker } from "@/lib/shadow-host-tracker";

type SendMessage = (message: unknown) => Promise<unknown>;
type DocumentIdSource = string | (() => string);

// A mutated element can only change discovery when it is a field, a form, or a
// container that holds one. Observing `class`/`style` on the whole document is
// necessary for late visibility changes, but a site that re-styles thousands of
// unrelated nodes must not schedule a rescan for each one.
const DISCOVERY_TARGET_SELECTOR = 'input,textarea,select,[contenteditable]:not([contenteditable="false"]),form,[role="form"]';
const DISCOVERY_TEXT_SELECTOR = 'label,legend,button,[role="button"],[role="heading"],h1,h2,h3,h4,form,[role="form"]';

function ownedUiNode(node: Node | null | undefined): boolean {
  return node instanceof Element && (node.matches(VAULTMESH_UI_SELECTOR) || node.closest(VAULTMESH_UI_SELECTOR) !== null);
}

function holdsDiscoverableFields(element: Element): boolean {
  if (element.matches(DISCOVERY_TARGET_SELECTOR)) return true;
  if (element.firstElementChild === null) return false;
  return element.querySelector(DISCOVERY_TARGET_SELECTOR) !== null;
}

/**
 * Only an inserted subtree that can carry fields justifies a rescan: it holds a
 * field itself, it is a custom element (possibly with a shadow root attached
 * later), or it already owns a shadow root. Feeds, carousels and chat lists
 * insert plain markup forever and must not each buy a document-wide walk.
 */
function mayCarryNewFields(element: Element): boolean {
  return holdsDiscoverableFields(element) || element.localName.includes("-") || accessibleShadowRoot(element) !== null;
}

function mutationNeedsRescan(record: MutationRecord): boolean {
  if (ownedUiNode(record.target)) return false;
  if (record.type === "childList") {
    // Bare text only matters where discovery reads text (labels, headings,
    // submit controls); arbitrary counter/chat text is not field semantics.
    const textRelevant = record.target instanceof Element && record.target.matches(DISCOVERY_TEXT_SELECTOR);
    for (const node of record.addedNodes) {
      if (ownedUiNode(node)) continue;
      if (node instanceof Element && mayCarryNewFields(node)) return true;
      if (node.nodeType === Node.TEXT_NODE && textRelevant) return true;
    }
    for (const node of record.removedNodes) {
      if (ownedUiNode(node)) continue;
      // Removal cannot introduce fields, so it needs no shadow-root probe.
      if (node instanceof Element && (holdsDiscoverableFields(node) || node.localName.includes("-"))) return true;
      if (node.nodeType === Node.TEXT_NODE && textRelevant) return true;
    }
    return false;
  }
  if (record.type === "attributes") {
    return record.target instanceof Element && holdsDiscoverableFields(record.target);
  }
  return false;
}

export function startAutofillPage(document: Document, documentId: DocumentIdSource, sendMessage: SendMessage, captureTarget?: (target: HTMLElement) => AutofillTarget | undefined) {
  const currentDocumentId = typeof documentId === "function" ? documentId : () => documentId;
  let disposed = false;
  let closeAssist: (() => void) | undefined;
  let revalidateTimer: ReturnType<typeof setTimeout> | null = null;
  let discoveryTimer: ReturnType<typeof setTimeout> | null = null;
  const pendingDiscovery = new Set<Element | ShadowRoot>();
  const knownDiscoveryScopes = new Set<Element | ShadowRoot>();
  let readySignatures = new WeakMap<ParentNode, string>();
  let pendingCaptureResumeTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingCaptureResumeAttempts = 0;
  let focusRequest = 0;
  let availabilityRequest = 0;
  let availability: "unknown" | "ready" | "locked" | "unavailable" = "unknown";
  type LoginAccountSession = {
    target: HTMLInputElement;
    pageContext: "login" | "unknown";
    loaded: boolean;
    typed: boolean;
    pendingPromise: Promise<unknown> | null;
    allCandidates: InlineAutofillCandidate[];
  };
  let activeLoginAccountSession: LoginAccountSession | null = null;
  let generatedCapture: { root: ParentNode; pageContext: "signup" | "password-change" | "password-reset"; loginId?: string } | null = null;
  let lastCapture: { signature: string; sentAt: number } | null = null;
  let activeCaptureId: string | null = null;
  type FilledFormState = { loginId?: string; identityId?: string; cardId?: string; loginEdited: boolean; identityEdited: boolean; cardEdited: boolean };
  const filledFormStates = new WeakMap<ParentNode, FilledFormState>();
  // Keystrokes must never run discovery. Controls the extension filled are
  // indexed directly; any other edit inside a filled form is matched by walking
  // ancestors, which is a bounded number of weak lookups.
  const filledControls = new WeakMap<Element, { state: FilledFormState; kind: string }>();
  const filledRoots = new WeakMap<Element, { state: FilledFormState; kind: string }>();
  const pendingCaptureKinds = new Map<string, { login: boolean; identity: boolean; card: boolean; root: ParentNode; state?: FilledFormState }>();
  const observers: MutationObserver[] = [];
  const observedRoots = new WeakSet<Node>();
  const shadowHosts = new ShadowHostTracker((root) => observeOpenRoots(root));
  const shadowEventRoots = new Set<ShadowRoot>();
  const handledEvents = new WeakSet<Event>();
  const menu = new InlineAutofillMenu(document, (candidate, target) => {
    if (candidate.kind === "device-assist") {
      if (!captureTarget?.(target)) return;
      closeAssist?.();
      closeAssist = openDeviceAssist(document, target, () => captureTarget?.(target), candidate.assistKind, sendMessage, candidate.assistKind === "sms" ? segmentedOtpAnchor(target) : target);
      return;
    }
    if (candidate.kind === "email-otp") {
      const scope = captureTarget?.(target);
      if (captureTarget && !scope) return;
      void sendMessage({ kind: "vaultmesh.email-otp-select", candidateId: candidate.id, ...(scope ? { target: scope } : {}) });
      return;
    }
    void selectCandidate(candidate, target);
  }, (login, target) => {
    if (classifyControl(target) !== "login") return;
    generatedCapture = { root: formRoot(target), pageContext: "signup" };
    void fillGeneratedLogin(document, currentDocumentId, login, target);
  }, (password, target) => {
    if (target instanceof HTMLInputElement) {
      const context = analyzeControlSemantics(target).context;
      if (context === "signup" || context === "password-change" || context === "password-reset") {
        const loginId = filledFormStates.get(formRoot(target))?.loginId;
        generatedCapture = { root: formRoot(target), pageContext: context, ...(context !== "signup" && loginId ? { loginId } : {}) };
      }
      void fillGeneratedPassword(document, currentDocumentId, target, password);
    }
  });
  const trigger = new InlineAutofillTrigger(document, (target) => void openCandidates(target));
  const savePrompt = new SaveCapturePrompt(document, async (captureId, decision) => {
    const response = SaveCaptureDecisionResponseSchema.safeParse(await sendMessage({
      kind: "vaultmesh.save-capture-decision",
      captureId,
      decision,
    }).catch(() => null));
    const result = response.success ? response.data : { status: "failed" as const };
    const kinds = pendingCaptureKinds.get(captureId);
    pendingCaptureKinds.delete(captureId);
    if (activeCaptureId === captureId) activeCaptureId = null;
    if (result.status === "saved" && kinds) {
      if (kinds.state) {
        if (kinds.login) kinds.state.loginEdited = false;
        if (kinds.identity) kinds.state.identityEdited = false;
        if (kinds.card) kinds.state.cardEdited = false;
      }
    } else {
      // Ignoring, timing out, or failing must allow the same user-edited data
      // to be offered again on the next real submission.
      lastCapture = null;
    }
    return result;
  });

  async function selectCandidate(candidate: AutofillCandidate, target: HTMLElement) {
    if (classifyControl(target) !== candidate.kind) return;
    const scope = captureTarget?.(target);
    if (captureTarget && !scope) return;
    // The desktop may need to revalidate or request a re-prompt. Do not let
    // that delayed result replace the UI after the user has moved to another
    // field (or the page lifecycle has invalidated this interaction).
    const request = ++focusRequest;
    const replaceExistingAccount = candidate.kind === "login" && !shouldPreserveExistingLoginAccount(target);
    const response = await sendMessage({
      kind: "vaultmesh.autofill-select",
      ...(scope ? { target: scope } : {}),
      selectedItem: {
        kind: candidate.kind,
        id: candidate.id,
        title: candidate.title,
        ...(candidate.masterPasswordReprompt ? { masterPasswordReprompt: true } : {}),
      },
      ...(replaceExistingAccount ? { replaceExistingAccount: true } : {}),
    }).catch(() => null);
    if (disposed || request !== focusRequest || !target.isConnected) return;
    if (fillResultStatus(response) === "unlock-required") {
      availability = "locked";
      trigger.setLocked(true);
    }
    const failure = inlineFillFailureMessage(response);
    if (failure) menu.showStatus(target, failure);
  }

  async function resumePendingCapture() {
    pendingCaptureResumeTimer = null;
    if (disposed || activeCaptureId || savePrompt.visible) return;
    pendingCaptureResumeAttempts += 1;
    const response = SaveCapturePendingResponseSchema.safeParse(
      await sendMessage({ kind: "vaultmesh.save-capture-pending" }).catch(() => null),
    );
    if (disposed || activeCaptureId || savePrompt.visible) return;
    if (response.success && response.data.status === "queued") {
      showPendingCapture(response.data);
      return;
    }
    if (response.success && response.data.status === "preparing" && pendingCaptureResumeAttempts < 240) {
      pendingCaptureResumeTimer = setTimeout(() => void resumePendingCapture(), 500);
    } else if (response.success && response.data.status === "none" && pendingCaptureResumeAttempts < 3) {
      pendingCaptureResumeTimer = setTimeout(() => void resumePendingCapture(), pendingCaptureResumeAttempts * 250);
    }
  }

  function showPendingCapture(details: import("@/lib/protocol").SaveCaptureQueuedResponse) {
    if (disposed || activeCaptureId && activeCaptureId !== details.captureId) return false;
    if (activeCaptureId === details.captureId) activeCaptureId = null;
    pendingCaptureKinds.delete(details.captureId);
    savePrompt.hide();
    return true;
  }

  async function refreshAvailability() {
    const request = ++availabilityRequest;
    const response = AutofillAvailabilityResponseSchema.safeParse(await sendMessage({ kind: "vaultmesh.autofill-state" }).catch(() => null));
    if (disposed || request !== availabilityRequest || !response.success) return availability;
    availability = response.data.status;
    trigger.setLocked(availability === "locked");
    return availability;
  }

  // A lifecycle edge may scan the document. Mutation work is always restricted
  // to a local subtree, including semantic clustering and target capture.
  const reportPageDiscovery = (scope: Document | Element | ShadowRoot = document) => {
    if (disposed || document.visibilityState === "hidden") return;
    if (scope instanceof Document) readySignatures = new WeakMap();
    withFieldDiscoveryCache(() => {
      const rawControls = formControls(scope);
      for (const control of rawControls) {
        let clusterRoot = semanticCluster(control).root;
        // Hidden formless controls have no eligible cluster yet. Retain their
        // structural container so revealing sibling wrappers can discover one
        // canonical cluster rather than issuing immediately invalid targets.
        if (clusterRoot === control) {
          for (let parent = control.parentElement; parent && !parent.matches("body,html"); parent = parent.parentElement) {
            if (scope instanceof Element && parent !== scope && !scope.contains(parent)) break;
            clusterRoot = parent;
            const ancestor = parent;
            const members = rawControls.filter((candidate) => ancestor.contains(candidate));
            if (members.length > 1 && members.some((candidate) => candidate instanceof HTMLInputElement && candidate.type === "password")) break;
          }
        }
        const local = clusterRoot instanceof Element || clusterRoot instanceof ShadowRoot ? clusterRoot : localDiscoveryScope(control);
        if (knownDiscoveryScopes.size < 256) knownDiscoveryScopes.add(local);
      }
      const { descriptors, handles } = discoverFields(scope);
      if (!hasLoginFields(descriptors)) return;
      const pageContext = selectAutofillPageContext(descriptors);
      if (pageContext !== "login" && pageContext !== "otp") return;
      const eligible = [...handles.values()].find((control) => classifyControl(control) === "login" && analyzeControlSemantics(control).context === pageContext);
      const target = eligible ? captureTarget?.(eligible) : undefined;
      if (captureTarget && !target) return;
      const root = eligible ? semanticCluster(eligible).root : scope;
      const cluster = eligible ? new Set([eligible, ...formControls(root)]) : null;
      const signature = loginFormSignature(cluster ? descriptors.filter((field) => cluster.has(handles.get(field.handle)!)) : descriptors);
      if (!signature || readySignatures.get(root) === signature) return;
      readySignatures.set(root, signature);
      void sendMessage({ kind: "vaultmesh.autofill-page-ready", documentId: currentDocumentId(), signature, pageContext, ...(target ? { target } : {}) });
    }, scope instanceof Document ? undefined : scope);
  };

  function localDiscoveryScope(element: Element): Element | ShadowRoot {
    const explicit = element instanceof HTMLInputElement ? element.form : null;
    if (explicit) return explicit;
    const form = element.closest('form,[role="form"],dialog,[role="dialog"],fieldset');
    if (form) return form;
    // Reuse the previously discovered canonical cluster for multi-step forms.
    // Bounding a new password to its immediate wrapper would mint a target
    // whose root cannot survive the normal, unscoped assignment revalidation.
    let known: Element | ShadowRoot | undefined;
    for (const scope of knownDiscoveryScopes) {
      if (!scope.isConnected || !scope.contains(element)) continue;
      if (!known || known.contains(scope)) known = scope;
    }
    if (known && known !== element) return known;
    if (element.matches(DISCOVERY_TARGET_SELECTOR)) {
      const parent = element.parentElement;
      if (parent && !parent.matches("body,html")) return parent;
      const root = element.getRootNode();
      if (root instanceof ShadowRoot) return root;
    }
    return element;
  }

  function schedulePageDiscovery(scope: Element | ShadowRoot) {
    if (disposed || scope === document.body || scope === document.documentElement) return;
    if (pendingDiscovery.size < 256) pendingDiscovery.add(scope);
    // Fixed window rather than a debounce: continuous mutation cannot starve it.
    if (discoveryTimer) return;
    discoveryTimer = setTimeout(() => {
      discoveryTimer = null;
      const scopes = [...pendingDiscovery];
      pendingDiscovery.clear();
      for (const local of scopes) if (local.isConnected) reportPageDiscovery(local);
    }, 100);
  }

  function composedContains(ancestor: Node, node: Node): boolean {
    for (let current: Node | null = node; current; current = current instanceof ShadowRoot ? current.host : current.parentNode) {
      if (current === ancestor) return true;
    }
    return false;
  }

  const scheduleTargetRevalidation = () => {
    if (disposed || revalidateTimer) return;
    revalidateTimer = setTimeout(() => {
      revalidateTimer = null;
      revalidateActiveTarget();
    }, 100);
  };

  /**
   * The one page state the periodic scan used to maintain: a field our UI is
   * attached to can lose eligibility (hidden, disabled, retyped) after we
   * showed the icon. Re-checking that single field is bounded work and keeps
   * the icon contract without re-walking the document.
   */
  const revalidateActiveTarget = () => {
    if (disposed) return;
    const target = trigger.target;
    if (!target) return;
    if (target.isConnected && withFieldDiscoveryCache(() => Boolean(classifyControl(target)), localDiscoveryScope(target))) return;
    focusRequest += 1;
    activeLoginAccountSession = null;
    menu.hide();
    trigger.hide();
  };

  const onMutations = (records: MutationRecord[]) => {
    if (disposed) return;
    let revalidate = false;
    for (const record of records) {
      if (ownedUiNode(record.target)) continue;
      const target = trigger.target;
      if (target && ((record.type === "attributes" && composedContains(record.target, target)) || [...record.removedNodes].some((node) => composedContains(node, target)))) revalidate = true;
      // Root observation is independent of field relevance. Plain wrappers may
      // contain nested custom hosts whose submit events are not composed.
      if (record.type === "childList") for (const node of record.addedNodes) {
        if (!(node instanceof Element) || ownedUiNode(node)) continue;
        observeOpenRoots(node);
        if (mayCarryNewFields(node)) schedulePageDiscovery(localDiscoveryScope(node));
      }
      // Ancestor visibility changes also affect controls across shadow hosts.
      if (record.type === "attributes") for (const scope of knownDiscoveryScopes) {
        if (!scope.isConnected) { knownDiscoveryScopes.delete(scope); continue; }
        if (composedContains(record.target, scope)) schedulePageDiscovery(scope);
      }
      if (!mutationNeedsRescan(record)) continue;
      if (target && record.target instanceof Element) {
        const scope = localDiscoveryScope(record.target);
        if (composedContains(scope, target)) revalidate = true;
      }
      if (record.type === "attributes" && record.target instanceof Element) schedulePageDiscovery(localDiscoveryScope(record.target));
      if (record.type === "childList" && record.target instanceof Element && record.target.matches(DISCOVERY_TEXT_SELECTOR)) {
        const form = record.target.closest('form,[role="form"],dialog,[role="dialog"],fieldset');
        if (form) schedulePageDiscovery(form);
      }
    }
    if (revalidate) scheduleTargetRevalidation();
  };

  /**
   * Registers observers on the given scope and every shadow root reachable from
   * it. Document and shadow roots are the observed units; an element scope only
   * contributes its own shadow root and its descendants.
   */
  function observeOpenRoots(root: ParentNode) {
    const roots: ParentNode[] = [root];
    for (let index = 0; index < roots.length; index += 1) {
      const current = roots[index]!;
      if (current instanceof Element) {
        if (current.matches(VAULTMESH_UI_SELECTOR)) continue;
        const ownRoot = accessibleShadowRoot(current);
        if (ownRoot) roots.push(ownRoot);
        else shadowHosts.watch(current);
        for (const child of current.children) roots.push(child);
        continue;
      }
      if (!observedRoots.has(current)) {
        const Observer = document.defaultView?.MutationObserver ?? MutationObserver;
        const observer = new Observer(onMutations);
        // SPA login screens frequently attach their semantic metadata after
        // mounting. Watch every attribute that discovery reads so a late ARIA
        // label or editable role can make the next one-shot fill eligible.
        // Values are deliberately excluded: rescans must never be driven by
        // page secrets and discovery continues to expose only `isEmpty`.
        observer.observe(current, { subtree: true, childList: true, attributes: true, attributeFilter: ["autocomplete", "type", "name", "id", "placeholder", "disabled", "readonly", "contenteditable", "role", "aria-label", "aria-labelledby", "aria-disabled", "aria-readonly", "aria-hidden", "hidden", "inert", "class", "style", "form"] });
        observers.push(observer);
        observedRoots.add(current);
        if (current instanceof ShadowRoot) {
          // Native submit is not composed; closed roots also retarget focus
          // and input. Subscribe at the root and deduplicate composed events.
          current.addEventListener("submit", onSubmit as EventListener, true);
          current.addEventListener("formdata", onFormData, true);
          current.addEventListener("keydown", onSubmissionKeyDown as EventListener, true);
          current.addEventListener("click", onClick as EventListener, true);
          current.addEventListener("focusin", onFocusIn as EventListener, true);
          current.addEventListener("input", onInput, true);
          shadowEventRoots.add(current);
          schedulePageDiscovery(current);
        }
      }
      for (const element of current.querySelectorAll<HTMLElement>("*")) {
        if (element.matches(VAULTMESH_UI_SELECTOR)) continue;
        const shadowRoot = accessibleShadowRoot(element);
        if (shadowRoot) roots.push(shadowRoot);
        else shadowHosts.watch(element);
      }
    }
  }

  async function deviceAssistEntries(target: HTMLElement): Promise<InlineAutofillCandidate[]> {
    const assistKind = deviceAssistKindForControl(target);
    if (!assistKind) return [];
    const support = await sendMessage({ kind: "vaultmesh.device-assist-capabilities" }).catch(() => null) as { supported?: boolean } | null;
    if (!support?.supported) return [];
    return [{ kind: "device-assist", id: "device-assist", assistKind, title: assistKind === "phone" ? "从手机填入号码" : "从手机获取验证码", subtitle: "已配对设备 · 在电脑点选填充" }];
  }

  function fetchLoginAccountCandidates(session: LoginAccountSession): Promise<unknown> {
    if (!session.pendingPromise) {
      const pending = sendMessage({
        kind: "vaultmesh.autofill-candidates",
        fieldKind: "login",
        pageContext: session.pageContext,
      }).then(
        (value) => {
          if (session.pendingPromise === pending) session.pendingPromise = null;
          return value;
        },
        () => {
          if (session.pendingPromise === pending) session.pendingPromise = null;
          return null;
        },
      );
      session.pendingPromise = pending;
    }
    return session.pendingPromise;
  }

  async function preloadLoginAccountCandidates(session: LoginAccountSession, request: number) {
    const raw = await fetchLoginAccountCandidates(session);
    if (
      disposed
      || request !== focusRequest
      || activeLoginAccountSession !== session
      || trigger.target !== session.target
      || !session.target.isConnected
      || classifyControl(session.target) !== "login"
    ) {
      return;
    }
    const response = AutofillCandidatesResponseSchema.safeParse(raw);
    if (!response.success || (response.data.status !== "ready" && response.data.status !== "locked")) return;
    const isLocked = response.data.status === "locked" || response.data.requiresUnlock === true;
    availability = isLocked ? "locked" : "ready";
    trigger.setLocked(isLocked);
    session.loaded = true;
    session.allCandidates = response.data.candidates.filter((candidate) => candidate.kind === "login");
    if (session.allCandidates.length === 0) {
      if (session.typed) menu.hide();
      return;
    }
    if (session.typed) {
      const filtered = filterCandidatesByTypedUsername(session.allCandidates, session.target.value);
      if (filtered.length > 0) menu.showFilteredCandidates(session.target, filtered);
      else menu.hide();
      return;
    }
    if (session.target.value === "") {
      menu.showFilteredCandidates(session.target, session.allCandidates);
    }
  }

  async function openCandidates(target: HTMLElement) {
    const fieldKind = classifyControl(target);
    if (!fieldKind) { menu.hide(); trigger.hide(); return; }
    if (target instanceof HTMLInputElement && isNewPasswordControl(target)) {
      const request = ++focusRequest;
      const options = await loadPasswordGeneratorOptions();
      if (disposed || request !== focusRequest || trigger.target !== target || !target.isConnected) return;
      menu.show(target, [], "password", { passwordGeneratorOptions: options });
      return;
    }
    const pageContext = analyzeControlSemantics(target).context;
    // Signup account fields create a new credential. Never offer existing
    // vault logins here; show the local random account/password generator.
    if (fieldKind === "login" && pageContext === "signup") {
      const request = ++focusRequest;
      const [passwordGeneratorOptions, usernameGeneratorOptions] = await Promise.all([
        loadPasswordGeneratorOptions(),
        loadUsernameGeneratorOptions(),
      ]);
      if (disposed || request !== focusRequest || trigger.target !== target || !target.isConnected) return;
      menu.show(target, [], "login", {
        generatedEmailRequired: isEmailAccountControl(target),
        passwordGeneratorOptions,
        usernameGeneratorOptions,
      });
      const deviceEntries = await deviceAssistEntries(target);
      if (deviceEntries.length && !disposed && request === focusRequest && trigger.target === target && target.isConnected) menu.show(target, deviceEntries, "login", {generatedEmailRequired: isEmailAccountControl(target), passwordGeneratorOptions, usernameGeneratorOptions});
      return;
    }
    const request = ++focusRequest;
    const rawResponse = activeLoginAccountSession?.target === target && activeLoginAccountSession.pageContext === pageContext && activeLoginAccountSession.pendingPromise
      ? await activeLoginAccountSession.pendingPromise
      : await sendMessage({ kind: "vaultmesh.autofill-candidates", fieldKind, pageContext }).catch(() => null);
    const response = AutofillCandidatesResponseSchema.safeParse(rawResponse);
    if (disposed || request !== focusRequest || trigger.target !== target || classifyControl(target) !== fieldKind) return;
    if (!response.success || (response.data.status !== "ready" && response.data.status !== "locked")) return menu.hide();
    const isLocked = response.data.status === "locked" || response.data.requiresUnlock === true;
    availability = isLocked ? "locked" : "ready";
    trigger.setLocked(isLocked);
    const candidates: InlineAutofillCandidate[] = response.data.candidates.filter((candidate) => candidate.kind === fieldKind);
    if (!isLocked && pageContext === "otp") {
      candidates.unshift(...(response.data.emailOtpCandidates ?? []).map((candidate) => ({
        ...candidate,
        kind: "email-otp" as const,
        title: candidate.code,
        subtitle: `来自 ${candidate.sourceDomain}`,
      })));
    }
    if (activeLoginAccountSession?.target === target) {
      activeLoginAccountSession.loaded = true;
      activeLoginAccountSession.allCandidates = [...candidates];
    }
    if (isLocked && candidates.length === 0) {
      const deviceEntries = await deviceAssistEntries(target);
      if (disposed || request !== focusRequest || trigger.target !== target || !target.isConnected) return;
      if (deviceEntries.length) {
        menu.show(target, deviceEntries, "none", { anchor: pageContext === "otp" ? segmentedOtpAnchor(target) : target });
      } else {
        menu.hide();
      }
      return;
    }
    // OTP controls reuse Login items as their data source, but an empty TOTP
    // candidate list is not a signup opportunity. Never fall back to the
    // random account/password generator for a verification-code field or while locked.
    const generatedMode = !isLocked && fieldKind === "login" && pageContext !== "otp" ? "login" : "none";
    menu.show(target, candidates, generatedMode, { anchor: pageContext === "otp" ? segmentedOtpAnchor(target) : target });
    const deviceEntries = await deviceAssistEntries(target);
    if (deviceEntries.length && !disposed && request === focusRequest && trigger.target === target && target.isConnected) menu.show(target, [...candidates, ...deviceEntries], generatedMode, {anchor: pageContext === "otp" ? segmentedOtpAnchor(target) : target});
  }

  async function refreshOtpCandidates() {
    focusRequest += 1;
    menu.hide();
    await sendMessage({ kind: "vaultmesh.autofill-candidates", fieldKind: "login", pageContext: "otp" }).catch(() => null);
  }

  const onFocusIn = (event: FocusEvent) => {
    if (handledEvents.has(event)) return;
    const target = event.composedPath()[0];
    if (menu.owns(event.target) || trigger.owns(event.target)) return;
    if (!(target instanceof Element)) {
      activeLoginAccountSession = null;
      menu.hide();
      return trigger.hide();
    }
    // One focus costs several semantic questions about the same field; answer
    // each of them once instead of re-walking the page per question.
    const { fieldKind, newPassword, loginAccountContext } = withFieldDiscoveryCache(() => {
      const kind = classifyControl(target);
      if (!kind) return { fieldKind: null, newPassword: false, loginAccountContext: null };
      const isNewPwd = isNewPasswordControl(target);
      const acctContext = kind === "login" && target instanceof HTMLInputElement && target.type !== "password" && !isNewPwd
        ? analyzeControlSemantics(target).context
        : null;
      return { fieldKind: kind, newPassword: isNewPwd, loginAccountContext: acctContext };
    });
    if (fieldKind) handledEvents.add(event);
    const request = ++focusRequest;
    menu.hide();
    if (!fieldKind) {
      activeLoginAccountSession = null;
      return trigger.hide();
    }
    trigger.show(target as HTMLElement, newPassword ? "generate-password" : "autofill", availability === "locked");
    if (loginAccountContext === "login" || loginAccountContext === "unknown") {
      activeLoginAccountSession = {
        target: target as HTMLInputElement,
        pageContext: loginAccountContext,
        loaded: false,
        typed: false,
        pendingPromise: null,
        allCandidates: [],
      };
      void preloadLoginAccountCandidates(activeLoginAccountSession, request);
    } else {
      activeLoginAccountSession = null;
    }
    void refreshAvailability();
  };

  const onPageHide = (event: PageTransitionEvent) => {
    if (!event.persisted) return dispose();

    // A document restored from the back-forward cache keeps its content
    // script alive. Do not permanently detach its discovery lifecycle, but
    // discard every page-scoped secret or UI state before the document is
    // frozen. The next pageshow performs a fresh, value-free discovery.
    clearPageScopedState();
  };
  const onPageShow = (event: PageTransitionEvent) => {
    if (!event.persisted || disposed) return;
    // A frozen document may have been rewritten by the page while our
    // observers delivered nothing, so this lifecycle edge re-registers roots.
    observeOpenRoots(document);
    reportPageDiscovery();
    void refreshAvailability();
    if (document.defaultView?.top === document.defaultView) void resumePendingCapture();
  };
  const invalidatePageContext = () => {
    if (disposed) return;
    clearPageScopedState();
    observeOpenRoots(document);
    reportPageDiscovery();
    void refreshAvailability();
  };
  const captureSubmission = (root: ParentNode) => {
    if (disposed) return;
    const pageUrl = document.defaultView?.location.href ?? "";
    const inferredContext = submittedDataContext(root);
    const generated = generatedCapture?.root === root ? generatedCapture : null;
    const pageContext = generated?.pageContext ?? inferredContext;
    const data: CapturedSaveData = captureSubmittedData(root, pageUrl, { context: pageContext });
    const filledState = filledFormStates.get(root);
    if (generated && data.login) {
      data.login = {
        username: data.login.username,
        password: data.login.password,
        ...(generated.loginId ? { loginId: generated.loginId } : {}),
      };
    } else if (data.login) {
      if (filledState?.loginId && !filledState.loginEdited) delete data.login;
      else if (filledState?.loginId && pageContext !== "signup") data.login.loginId = filledState.loginId;
    }
    if (data.identity) {
      if (filledState?.identityId && !filledState.identityEdited) delete data.identity;
      else if (filledState?.identityId) data.identity.identityId = filledState.identityId;
    }
    if (data.card) {
      if (filledState?.cardId && !filledState.cardEdited) delete data.card;
      else if (filledState?.cardId) data.card.cardId = filledState.cardId;
    }

    const captureHasData = hasCapturedData(data);
    const submittedUsername = data.login?.username || accountValue(root);
    if (!captureHasData && submittedUsername && (pageContext === "login" || pageContext === "signup")) {
      void sendMessage({ kind: "vaultmesh.account-stage", pageUrl, username: submittedUsername });
    }
    if (!captureHasData) return;
    const signature = capturedDataSignature(data);
    if (lastCapture?.signature === signature && Date.now() - lastCapture.sentAt < 2_000) return;
    lastCapture = { signature, sentAt: Date.now() };
    if (generated) generatedCapture = null;
    const captureId = createUuid();
    const supersededCaptureId = activeCaptureId;
    activeCaptureId = captureId;
    const captureRequest = sendMessage({ kind: "vaultmesh.save-capture", captureId, pageUrl, pageContext, data });
    if (supersededCaptureId) {
      pendingCaptureKinds.delete(supersededCaptureId);
      void sendMessage({
        kind: "vaultmesh.save-capture-decision",
        captureId: supersededCaptureId,
        decision: "ignore",
      }).catch(() => undefined);
    }
    pendingCaptureKinds.set(captureId, { login: Boolean(data.login), identity: Boolean(data.identity), card: Boolean(data.card), root, state: filledState });
    // Account/card/identity checks can resolve to `unchanged`. Keep that
    // preparatory state invisible so an unchanged submission does not flash a
    // misleading save prompt immediately before a full-page navigation.
    savePrompt.showPreparing(capturePromptDetails(captureId, pageUrl, data), false);
    void captureRequest
      .then((response) => {
        const queued = SaveCaptureQueuedResponseSchema.safeParse(response);
        if (disposed) return;
        if (activeCaptureId !== captureId) {
          if (queued.success) {
            void sendMessage({ kind: "vaultmesh.save-capture-decision", captureId, decision: "ignore" }).catch(() => undefined);
          }
          return;
        }
        if (queued.success && queued.data.captureId === captureId) showPendingCapture(queued.data);
        else if (isResponseStatus(response, "unchanged")) {
          const unchanged = pendingCaptureKinds.get(captureId);
          if (unchanged?.state) {
            if (unchanged.login) unchanged.state.loginEdited = false;
            if (unchanged.identity) unchanged.state.identityEdited = false;
            if (unchanged.card) unchanged.state.cardEdited = false;
          }
          pendingCaptureKinds.delete(captureId);
          activeCaptureId = null;
          savePrompt.hide();
        }
        else {
          pendingCaptureKinds.delete(captureId);
          lastCapture = null;
          activeCaptureId = null;
          if (isResponseStatus(response, "queued")) savePrompt.showQueueFailure(captureId, "background-outdated");
          else if (isResponseStatus(response, "account-check-failed")) savePrompt.showQueueFailure(captureId, "account-check-failed");
          else if (isResponseStatus(response, "save-check-failed")) savePrompt.showQueueFailure(captureId, "save-check-failed");
          else if (isResponseStatus(response, "unsupported-page")) savePrompt.showQueueFailure(captureId, "unsupported-page");
          else savePrompt.showQueueFailure(captureId, response == null ? "background-unavailable" : "invalid-response");
        }
      })
      .catch(() => {
        if (activeCaptureId !== captureId) return;
        pendingCaptureKinds.delete(captureId);
        lastCapture = null;
        activeCaptureId = null;
        savePrompt.showQueueFailure(captureId, "background-unavailable");
      });
  };
  const onSubmit = (event: SubmitEvent) => {
    const target = event.composedPath()[0];
    if (handledEvents.has(event) || !(target instanceof HTMLFormElement)) return;
    handledEvents.add(event);
    captureSubmission(target);
  };
  const onFormData = (event: Event) => {
    // The browser constructs form data even for form.submit(), which bypasses
    // submit listeners. Inspect only the associated DOM form, never serialize
    // arbitrary FormData entries (uploads and unrelated fields included).
    const target = event.composedPath()[0];
    if (handledEvents.has(event) || !(target instanceof HTMLFormElement)) return;
    handledEvents.add(event);
    captureSubmission(target);
  };
  const onSubmissionKeyDown = (event: KeyboardEvent) => {
    if (event.key !== "Enter" || event.isComposing || event.defaultPrevented || menu.visible || handledEvents.has(event)) return;
    const target = event.composedPath()[0];
    if (!(target instanceof HTMLInputElement)) return;
    handledEvents.add(event);
    // Submission handling asks several semantic questions about one field and
    // then reads the whole form; share one discovery pass for all of it.
    withFieldDiscoveryCache(() => {
      if (!classifyControl(target) || analyzeControlSemantics(target).context === "otp") return;
      const root = formRoot(target);
      if (root instanceof HTMLFormElement && !root.checkValidity() || root.querySelector('[aria-invalid="true"]')) return;
      captureSubmission(root);
    });
  };
  const onClick = (event: MouseEvent) => {
    if (handledEvents.has(event)) return;
    const target = event.composedPath()[0];
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLElement>('button,input[type="submit"],input[type="button"],[role="button"]');
    if (!button) return;
    handledEvents.add(event);
    if (event.isTrusted && isOtpRequestAction(button)) void sendMessage({ kind: "vaultmesh.otp-watch-requested" }).catch(() => undefined);
    if (!isSaveAction(button)) return;
    const root = submissionRoot(button);
    if (!root) return;
    if (root instanceof HTMLFormElement && !root.checkValidity() || root.querySelector('[aria-invalid="true"]')) return;
    // Read while the submitting controls still exist: SPA click handlers can
    // synchronously unmount them. This only queues a confirmation, never save.
    captureSubmission(root);
  };
  const onInput = (event: Event) => {
    const target = event.composedPath()[0];
    if (!event.isTrusted || !(target instanceof Element) || handledEvents.has(event)) return;
    // Editing is recorded only for forms this controller filled, and typing in
    // the active login account input filters already-cached candidates in memory.
    // Running field classification per keystroke re-entered discovery on every character.
    let handled = markFilledEdit(target, null);
    if (activeLoginAccountSession && target === activeLoginAccountSession.target) {
      handled = true;
      const session = activeLoginAccountSession;
      session.typed = true;
      if (session.loaded) {
        const filtered = filterCandidatesByTypedUsername(session.allCandidates, session.target.value);
        if (filtered.length > 0) menu.showFilteredCandidates(session.target, filtered);
        else menu.hide();
      } else {
        void preloadLoginAccountCandidates(session, focusRequest);
      }
    }
    if (handled) handledEvents.add(event);
  };
  const markFilledEdit = (target: Element, kind: string | null): boolean => {
    const direct = filledControls.get(target);
    if (direct) {
      applyEditedFlag(direct.state, kind ?? direct.kind);
      return true;
    }
    let ancestor: Element | null = target;
    for (let depth = 0; ancestor && depth < 32; ancestor = ancestor.parentElement, depth += 1) {
      const filled = filledRoots.get(ancestor);
      if (!filled) continue;
      applyEditedFlag(filled.state, kind ?? filled.kind);
      return true;
    }
    return false;
  };
  const applyEditedFlag = (state: FilledFormState, kind: string) => {
    if (kind === "login") state.loginEdited = true;
    if (kind === "identity") state.identityEdited = true;
    if (kind === "card") state.cardEdited = true;
  };
  const recordEditedItem = (kind: string | null | undefined, target?: Element | ParentNode) => {
    const root = target instanceof Element ? formRoot(target) : target;
    if (!root) return;
    const state = filledFormStates.get(root);
    if (!state) return;
    if (kind === "login") state.loginEdited = true;
    if (kind === "identity") state.identityEdited = true;
    if (kind === "card") state.cardEdited = true;
  };
  const onVisibilityChange = () => {
    if (document.visibilityState === "hidden") {
      menu.hide();
      trigger.hide();
    }
    else {
      reportPageDiscovery();
      void refreshAvailability();
    }
  };
  document.addEventListener("focusin", onFocusIn, true);
  document.addEventListener("submit", onSubmit, true);
  document.addEventListener("formdata", onFormData, true);
  document.addEventListener("keydown", onSubmissionKeyDown, true);
  document.addEventListener("click", onClick, true);
  document.addEventListener("input", onInput, true);
  document.addEventListener("visibilitychange", onVisibilityChange);
  // `pagehide` can fire once for a BFCache suspension and again when the
  // restored document really navigates away. It must remain subscribed after
  // the first event so the latter path still tears down page-owned UI.
  document.defaultView?.addEventListener("pagehide", onPageHide);
  document.defaultView?.addEventListener("pageshow", onPageShow);
  observeOpenRoots(document);
  reportPageDiscovery();
  void refreshAvailability();
  if (document.defaultView?.top === document.defaultView) void resumePendingCapture();

  function dispose() {
    if (disposed) return;
    disposed = true;
    closeAssist?.();
    if (revalidateTimer) clearTimeout(revalidateTimer);
    if (discoveryTimer) clearTimeout(discoveryTimer);
    discoveryTimer = null;
    pendingDiscovery.clear();
    knownDiscoveryScopes.clear();
    readySignatures = new WeakMap();
    shadowHosts.reset();
    if (pendingCaptureResumeTimer) clearTimeout(pendingCaptureResumeTimer);
    for (const observer of observers) observer.disconnect();
    for (const root of shadowEventRoots) {
      root.removeEventListener("submit", onSubmit as EventListener, true);
      root.removeEventListener("formdata", onFormData, true);
      root.removeEventListener("keydown", onSubmissionKeyDown as EventListener, true);
      root.removeEventListener("click", onClick as EventListener, true);
      root.removeEventListener("focusin", onFocusIn as EventListener, true);
      root.removeEventListener("input", onInput, true);
    }
    shadowEventRoots.clear();
    document.removeEventListener("focusin", onFocusIn, true);
    document.removeEventListener("submit", onSubmit, true);
    document.removeEventListener("formdata", onFormData, true);
    document.removeEventListener("keydown", onSubmissionKeyDown, true);
    document.removeEventListener("click", onClick, true);
    document.removeEventListener("input", onInput, true);
    document.removeEventListener("visibilitychange", onVisibilityChange);
    document.defaultView?.removeEventListener("pagehide", onPageHide);
    document.defaultView?.removeEventListener("pageshow", onPageShow);
    menu.destroy();
    trigger.destroy();
    savePrompt.destroy();
  }

  function clearPageScopedState() {
    generatedCapture = null;
    lastCapture = null;
    activeLoginAccountSession = null;
    // Invalidate pending UI and availability work before a BFCache freeze.
    // A capture confirmation is desktop-owned and may survive navigation, so
    // its opaque id is intentionally not cancelled here.
    focusRequest += 1;
    availabilityRequest += 1;
    pendingCaptureResumeAttempts = 0;
    if (revalidateTimer) clearTimeout(revalidateTimer);
    if (discoveryTimer) clearTimeout(discoveryTimer);
    discoveryTimer = null;
    pendingDiscovery.clear();
    knownDiscoveryScopes.clear();
    readySignatures = new WeakMap();
    shadowHosts.reset();
    if (pendingCaptureResumeTimer) clearTimeout(pendingCaptureResumeTimer);
    revalidateTimer = null;
    pendingCaptureResumeTimer = null;
    menu.hide();
    trigger.hide();
    savePrompt.hide();
  }

  function recordFilledItem(item: { kind: string; id: string }, controls: Iterable<Element> = []) {
    const roots = new Map<ParentNode, FilledFormState>();
    for (const control of controls) {
      const root = formRoot(control);
      const state = roots.get(root) ?? filledFormStates.get(root) ?? { loginEdited: false, identityEdited: false, cardEdited: false };
      if (item.kind === "login") { state.loginId = item.id; state.loginEdited = false; }
      if (item.kind === "identity") { state.identityId = item.id; state.identityEdited = false; }
      if (item.kind === "card") { state.cardId = item.id; state.cardEdited = false; }
      roots.set(root, state);
      filledControls.set(control, { state, kind: item.kind });
      if (root instanceof Element) filledRoots.set(root, { state, kind: item.kind });
    }
    for (const [root, state] of roots) filledFormStates.set(root, state);
  }

  async function completePasswordChange(item: { kind: string; id: string }, controls: Iterable<Element> = []) {
    if (item.kind !== "login" || disposed) return { status: "not-applicable" as const };
    const requestDocumentId = currentDocumentId();
    const currentPassword = Array.from(controls).find((control): control is HTMLInputElement => {
      if (!(control instanceof HTMLInputElement) || control.type !== "password") return false;
      const semantics = analyzeControlSemantics(control);
      return semantics.context === "password-change" && semantics.confidence !== "low" && credentialFieldRole(control) === "current-password";
    });
    if (!currentPassword) return { status: "not-applicable" as const };

    const emptyNewPasswordFields = () => passwordFieldGroup(currentPassword)
      .filter((control) => isNewPasswordControl(control));
    let newPasswordFields = emptyNewPasswordFields();
    if (newPasswordFields.length === 0) return { status: "not-applicable" as const };
    if (newPasswordFields.some((control) => control.value !== "")) return { status: "preserved-existing" as const };

    try {
      const options = await loadPasswordGeneratorOptions();
      if (disposed || currentDocumentId() !== requestDocumentId || !currentPassword.isConnected) return { status: "cancelled" as const };
      newPasswordFields = emptyNewPasswordFields();
      if (newPasswordFields.length === 0) return { status: "not-applicable" as const };
      if (newPasswordFields.some((control) => control.value !== "")) return { status: "preserved-existing" as const };

      const password = generatePassword(options);
      generatedCapture = { root: formRoot(currentPassword), pageContext: "password-change", loginId: item.id };
      const result = await fillGeneratedPassword(document, currentDocumentId, newPasswordFields[0]!, password);
      if (result.results.length !== newPasswordFields.length || result.results.some((entry) => entry.status !== "filled")) {
        generatedCapture = null;
        return { status: "failed" as const };
      }
      return { status: "generated" as const };
    } catch {
      generatedCapture = null;
      return { status: "failed" as const };
    }
  }

  return { dispose, menu, trigger, savePrompt, scan: reportPageDiscovery, invalidatePageContext, refreshOtpCandidates, recordFilledItem, completePasswordChange, recordEditedItem, showPendingCapture };
}

function segmentedOtpAnchor(target: HTMLElement) {
  if (!(target instanceof HTMLInputElement)) return target;
  for (let container = target.parentElement; container; container = container.parentElement) {
    const inputs = Array.from(container.querySelectorAll<HTMLInputElement>("input"));
    const otpInputs = inputs.filter((input) => analyzeControlSemantics(input).context === "otp");
    // Only a group of digit cells is one logical code field. A phone number
    // and a single code box share the "otp" page context but must keep their
    // own anchors, otherwise the menu opens below the neighbouring field.
    const cells = otpInputs.length === inputs.length && otpInputs.includes(target)
      && (otpInputs.length >= 4 || otpInputs.every((input) => input.maxLength > 0 && input.maxLength <= 2));
    if (cells && otpInputs.length >= 2) return container;
    if (container.matches('form,[role="form"],body,html')) break;
  }
  return target;
}

function formRoot(element: Element): ParentNode {
  return semanticCluster(element as HTMLElement).root;
}

function submissionRoot(button: HTMLElement): ParentNode | null {
  if ((button instanceof HTMLButtonElement || button instanceof HTMLInputElement) && button.form) return button.form;
  const explicit = button.closest("form,[role='form']");
  if (explicit) return explicit;
  for (let root: ParentNode | null = button.parentNode; root && root !== button.ownerDocument.body && root !== button.ownerDocument; root = root.parentNode) {
    const controls = formControls(root);
    if (controls.length) return semanticCluster(controls[0]!).root;
  }
  return null;
}

function capturePromptDetails(captureId: string, pageUrl: string, data: CapturedSaveData) {
  let hostname = "当前网站";
  try { hostname = new URL(pageUrl).hostname || hostname; } catch { /* Keep a non-sensitive fallback label. */ }
  const labels = [data.login ? "登录信息" : "", data.identity ? "个人资料/地址" : "", data.card ? "支付卡" : ""].filter(Boolean);
  return { captureId, hostname, labels, update: Boolean(data.login?.loginId) };
}

function isResponseStatus(response: unknown, status: string): boolean {
  return Boolean(response && typeof response === "object" && "status" in response && response.status === status);
}

function accountValue(root: ParentNode): string {
  const controls = formControls(root).filter((control): control is HTMLInputElement => control instanceof HTMLInputElement && control.type !== "password");
  const explicit = controls.find((control) => {
    const metadata = `${control.autocomplete} ${control.name} ${control.id} ${control.placeholder}`;
    return /username|email|account|login|phone|mobile|用户名|账号|邮箱|手机/i.test(metadata);
  });
  return explicit?.value ?? "";
}

function isSaveAction(button: HTMLElement) {
  if (button instanceof HTMLInputElement && button.type === "submit") return true;
  if (button instanceof HTMLButtonElement && button.type === "submit") return true;
  const text = `${button instanceof HTMLInputElement ? button.value : button.textContent ?? ""} ${button.getAttribute("aria-label") ?? ""}`;
  return /sign\s*in|log\s*in|sign\s*up|register|create|continue|next|save|submit|update|change.{0,12}(?:password|passcode)|checkout|pay|登录|注册|创建|继续|下一步|保存|提交|更新|修改.{0,8}(?:密码|口令)|结账|支付/i.test(text);
}

export function isOtpRequestAction(button: HTMLElement) {
  const text = button instanceof HTMLInputElement
    ? `${button.value} ${button.getAttribute("aria-label") ?? ""}`
    : `${button.textContent ?? ""} ${button.getAttribute("aria-label") ?? ""}`;
  return /(?:获取|发送|重新发送|重发|取得).{0,8}(?:验证码|校验码|动态码)|(?:验证码|校验码|动态码).{0,8}(?:获取|发送|重发)|(?:get|send|request|resend).{0,12}(?:verification|security|one[-\s]*time|otp).{0,8}(?:code|password)?|(?:verification|security|otp).{0,8}(?:code)?.{0,12}(?:send|resend)/i.test(text);
}

export type { InlineAutofillCandidate };
