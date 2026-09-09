import { accessibleShadowRoot, analyzeControlSemantics, credentialFieldRole, discoverFields, classifyControl, formControls, semanticCluster, hasLoginFields, isEmailAccountControl, isNewPasswordControl, loginFormSignature, passwordFieldGroup, selectAutofillPageContext, shouldPreserveExistingLoginAccount } from "@/lib/form-discovery";
import { InlineAutofillMenu } from "@/lib/inline-autofill";
import { InlineAutofillTrigger } from "@/lib/inline-autofill-trigger";
import { fillResultStatus, inlineFillFailureMessage } from "@/lib/autofill-selection";
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

export function startAutofillPage(document: Document, documentId: DocumentIdSource, sendMessage: SendMessage, captureTarget?: (target: HTMLElement) => AutofillTarget | undefined) {
  const currentDocumentId = typeof documentId === "function" ? documentId : () => documentId;
  let disposed = false;
  let scanTimer: ReturnType<typeof setTimeout> | null = null;
  let unlockPollTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingCaptureResumeTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingCaptureResumeAttempts = 0;
  let unlockPollRemaining = 0;
  let focusRequest = 0;
  let availabilityRequest = 0;
  let availability: "unknown" | "ready" | "locked" | "unavailable" = "unknown";
  let generatedCapture: { root: ParentNode; pageContext: "signup" | "password-change" | "password-reset"; loginId?: string } | null = null;
  let lastCapture: { signature: string; sentAt: number } | null = null;
  let activeCaptureId: string | null = null;
  type FilledFormState = { loginId?: string; identityId?: string; cardId?: string; loginEdited: boolean; identityEdited: boolean; cardEdited: boolean };
  const filledFormStates = new WeakMap<ParentNode, FilledFormState>();
  const pendingCaptureKinds = new Map<string, { login: boolean; identity: boolean; card: boolean; root: ParentNode; state?: FilledFormState }>();
  const observers: MutationObserver[] = [];
  const observedRoots = new WeakSet<Node>();
  const shadowHosts = new ShadowHostTracker((root) => { observeOpenRoots(root); scheduleScan(); });
  const shadowEventRoots = new Set<ShadowRoot>();
  const handledEvents = new WeakSet<Event>();
  const menu = new InlineAutofillMenu(document, (candidate, target) => {
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

  function openUnlock() {
    menu.hide();
    void sendMessage({ kind: "vaultmesh.open-unlock" });
    unlockPollRemaining = 120;
    if (unlockPollTimer) clearTimeout(unlockPollTimer);
    const poll = async () => {
      unlockPollTimer = null;
      const state = await refreshAvailability();
      unlockPollRemaining -= 1;
      if (!disposed && state !== "ready" && unlockPollRemaining > 0) unlockPollTimer = setTimeout(poll, 1_000);
    };
    unlockPollTimer = setTimeout(poll, 750);
  }

  const scan = () => {
    if (disposed || document.visibilityState === "hidden") return;
    observeOpenRoots(document);
    if (trigger.target && !classifyControl(trigger.target)) {
      focusRequest += 1;
      menu.hide();
      trigger.hide();
    }
    const { descriptors, handles } = discoverFields(document);
    if (!hasLoginFields(descriptors)) return;
    const pageContext = selectAutofillPageContext(descriptors);
    if (pageContext !== "login" && pageContext !== "otp") return;
    const eligible = [...handles.values()].find((control) => classifyControl(control) === "login" && analyzeControlSemantics(control).context === pageContext);
    const target = eligible ? captureTarget?.(eligible) : undefined;
    if (captureTarget && !target) return;
    const cluster = eligible ? new Set([eligible, ...formControls(semanticCluster(eligible).root)]) : null;
    const signature = loginFormSignature(cluster ? descriptors.filter((field) => cluster.has(handles.get(field.handle)!)) : descriptors);
    if (signature) void sendMessage({ kind: "vaultmesh.autofill-page-ready", documentId: currentDocumentId(), signature, pageContext, ...(target ? { target } : {}) });
  };

  const scheduleScan = () => {
    if (disposed || scanTimer) return;
    scanTimer = setTimeout(() => {
      scanTimer = null;
      scan();
    }, 150);
  };

  function observeOpenRoots(root: Document | ShadowRoot) {
    const roots: Array<Document | ShadowRoot> = [root];
    for (let index = 0; index < roots.length; index += 1) {
      const current = roots[index]!;
      if (!observedRoots.has(current)) {
        const Observer = document.defaultView?.MutationObserver ?? MutationObserver;
        const observer = new Observer(scheduleScan);
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
        }
      }
      for (const element of current.querySelectorAll<HTMLElement>("*")) {
        if (element.matches("[data-vaultmesh-autofill],[data-vaultmesh-autofill-trigger]")) continue;
        const shadowRoot = accessibleShadowRoot(element);
        if (shadowRoot) roots.push(shadowRoot);
        else shadowHosts.watch(element);
      }
    }
  }

  async function openCandidates(target: HTMLElement) {
    const fieldKind = classifyControl(target);
    if (!fieldKind) { menu.hide(); trigger.hide(); return; }
    if (availability === "locked") return openUnlock();
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
      return;
    }
    const request = ++focusRequest;
    const response = AutofillCandidatesResponseSchema.safeParse(await sendMessage({ kind: "vaultmesh.autofill-candidates", fieldKind, pageContext }).catch(() => null));
    if (disposed || request !== focusRequest || trigger.target !== target || classifyControl(target) !== fieldKind) return;
    if (response.success && response.data.status === "locked") {
      availability = "locked";
      trigger.setLocked(true);
      return openUnlock();
    }
    if (!response.success || response.data.status !== "ready") return menu.hide();
    const candidates: InlineAutofillCandidate[] = response.success && response.data.status === "ready"
      ? response.data.candidates.filter((candidate) => candidate.kind === fieldKind)
      : [];
    if (pageContext === "otp") {
      candidates.unshift(...(response.data.emailOtpCandidates ?? []).map((candidate) => ({
        ...candidate,
        kind: "email-otp" as const,
        title: candidate.code,
        subtitle: `来自 ${candidate.sourceDomain}`,
      })));
    }
    // OTP controls reuse Login items as their data source, but an empty TOTP
    // candidate list is not a signup opportunity. Never fall back to the
    // random account/password generator for a verification-code field.
    const generatedMode = fieldKind === "login" && pageContext !== "otp" ? "login" : "none";
    menu.show(target, candidates, generatedMode, { anchor: pageContext === "otp" ? segmentedOtpAnchor(target) : target });
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
      menu.hide();
      return trigger.hide();
    }
    const fieldKind = classifyControl(target);
    if (fieldKind) handledEvents.add(event);
    focusRequest += 1;
    menu.hide();
    if (!fieldKind) return trigger.hide();
    trigger.show(target as HTMLElement, isNewPasswordControl(target) ? "generate-password" : "autofill", availability === "locked");
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
    scheduleScan();
    void refreshAvailability();
    if (document.defaultView?.top === document.defaultView) void resumePendingCapture();
  };
  const invalidatePageContext = () => {
    if (disposed) return;
    clearPageScopedState();
    scheduleScan();
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
    if (!(target instanceof HTMLInputElement) || !classifyControl(target) || analyzeControlSemantics(target).context === "otp") return;
    const root = formRoot(target);
    if (root instanceof HTMLFormElement && !root.checkValidity() || root.querySelector('[aria-invalid="true"]')) return;
    handledEvents.add(event);
    captureSubmission(root);
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
    const kind = classifyControl(target);
    if (kind) handledEvents.add(event);
    recordEditedItem(kind, target);
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
      scheduleScan();
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
  scheduleScan();
  void refreshAvailability();
  if (document.defaultView?.top === document.defaultView) void resumePendingCapture();

  function dispose() {
    if (disposed) return;
    disposed = true;
    if (scanTimer) clearTimeout(scanTimer);
    shadowHosts.reset();
    if (unlockPollTimer) clearTimeout(unlockPollTimer);
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
    // Invalidate pending UI and availability work before a BFCache freeze.
    // A capture confirmation is desktop-owned and may survive navigation, so
    // its opaque id is intentionally not cancelled here.
    focusRequest += 1;
    availabilityRequest += 1;
    unlockPollRemaining = 0;
    pendingCaptureResumeAttempts = 0;
    if (scanTimer) clearTimeout(scanTimer);
    shadowHosts.reset();
    if (unlockPollTimer) clearTimeout(unlockPollTimer);
    if (pendingCaptureResumeTimer) clearTimeout(pendingCaptureResumeTimer);
    scanTimer = null;
    unlockPollTimer = null;
    pendingCaptureResumeTimer = null;
    menu.hide();
    trigger.hide();
    savePrompt.hide();
  }

  function recordFilledItem(item: { kind: string; id: string }, controls: Iterable<Element> = []) {
    const roots = new Set(Array.from(controls, formRoot));
    for (const root of roots) {
      const state = filledFormStates.get(root) ?? { loginEdited: false, identityEdited: false, cardEdited: false };
      if (item.kind === "login") { state.loginId = item.id; state.loginEdited = false; }
      if (item.kind === "identity") { state.identityId = item.id; state.identityEdited = false; }
      if (item.kind === "card") { state.cardId = item.id; state.cardEdited = false; }
      filledFormStates.set(root, state);
    }
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

  return { dispose, menu, trigger, savePrompt, scan: scheduleScan, invalidatePageContext, refreshOtpCandidates, recordFilledItem, completePasswordChange, recordEditedItem, showPendingCapture };
}

function segmentedOtpAnchor(target: HTMLElement) {
  if (!(target instanceof HTMLInputElement)) return target;
  for (let container = target.parentElement; container; container = container.parentElement) {
    const otpInputs = Array.from(container.querySelectorAll<HTMLInputElement>("input"))
      .filter((input) => analyzeControlSemantics(input).context === "otp");
    if (otpInputs.length >= 2 && otpInputs.includes(target)) return container;
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
