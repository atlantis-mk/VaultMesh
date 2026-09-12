import { AutofillScriptGenerator } from "./autofill-script-generator";
import {
  filter,
  firstValueFrom,
  merge,
  Observable,
  ReplaySubject,
  scan,
  startWith,
  timer,
} from "rxjs";
import { map, pairwise, share, takeUntil } from "rxjs/operators";

import { AccountInfo, AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { AuthService } from "@bitwarden/common/auth/abstractions/auth.service";
import { UserVerificationService } from "@bitwarden/common/auth/abstractions/user-verification/user-verification.service.abstraction";
import { AuthenticationStatus } from "@bitwarden/common/auth/enums/authentication-status";
import { getOptionalUserId } from "@bitwarden/common/auth/services/account.service";
import {
  AutofillOverlayVisibility,
  AutofillTargetingRuleTypes,
  CardExpiryDateDelimiters,
  FormPurposeCategories,
} from "@bitwarden/common/autofill/constants";
import { AutofillSettingsServiceAbstraction } from "@bitwarden/common/autofill/services/autofill-settings.service";
import { DomainSettingsService } from "@bitwarden/common/autofill/services/domain-settings.service";
import { UserNotificationSettingsServiceAbstraction } from "@bitwarden/common/autofill/services/user-notification-settings.service";
import { InlineMenuVisibilitySetting } from "@bitwarden/common/autofill/types";
import { normalizeExpiryYearFormat } from "@bitwarden/common/autofill/utils";
import { BillingAccountProfileStateService } from "@bitwarden/common/billing/abstractions/account/billing-account-profile-state.service";
import { EventCollectionService, EventType } from "@bitwarden/common/dirt/event-logs";
import {
  UriMatchStrategySetting,
  UriMatchStrategy,
} from "@bitwarden/common/models/domain/domain-service";
import { AnimationControlService } from "@bitwarden/common/platform/abstractions/animation-control.service";
import { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import { MessageListener } from "@bitwarden/common/platform/messaging";
import { UserId } from "@bitwarden/common/types/guid";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { TotpService } from "@bitwarden/common/vault/abstractions/totp.service";
import { FieldType, CipherType } from "@bitwarden/common/vault/enums";
import { CipherRepromptType } from "@bitwarden/common/vault/enums/cipher-reprompt-type";
import { CardView } from "@bitwarden/common/vault/models/view/card.view";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { FieldView } from "@bitwarden/common/vault/models/view/field.view";
import { IdentityView } from "@bitwarden/common/vault/models/view/identity.view";

import { BrowserApi } from "../../platform/browser/browser-api";
import { ScriptInjectorService } from "../../platform/services/abstractions/script-injector.service";
import { getWebExtSender } from "../../platform/utils/web-ext-sender";
// FIXME (PM-22628): Popup imports are forbidden in background
// eslint-disable-next-line no-restricted-imports
import { openVaultItemPasswordRepromptPopout } from "../../vault/popup/utils/vault-popout-window";
import { AutofillMessageCommand, AutofillMessageSender } from "../enums/autofill-message.enums";
import { InlineMenuFillTypes, type InlineMenuFillType } from "../enums/autofill-overlay.enum";
import AutofillField from "../models/autofill-field";
import AutofillPageDetails from "../models/autofill-page-details";
import AutofillScript from "../models/autofill-script";
import { fieldContainsKeyword, isNonLoginUsernameField } from "../utils/qualification";

import { AutofillLifecycleService } from "./abstractions/autofill-lifecycle.service";
import {
  AutoFillOptions,
  AutoFillResult,
  AutofillService as AutofillServiceInterface,
  COLLECT_PAGE_DETAILS_RESPONSE_COMMAND,
  FormData,
  GenerateFillScriptOptions,
  PageDetail,
} from "./abstractions/autofill.service";
import {
  AutoFillConstants,
  CardExpiryDateFormat,
  CreditCardAutoFillConstants,
  IdentityAutoFillConstants,
  SshKeyAutoFillConstants,
} from "./autofill-constants";

/**
 * A Login cipher stores a single `login.username` that represents whatever the
 * primary login identifier is (an actual username, an email, or a phone number).
 * A targeting-rule `account-login` form may expose that identifier under any of
 * these field types (and often has no `username` field at all). When filling a
 * Login cipher, route `login.username` to the highest-priority identifier field
 * present in the form, in this order, and skip the others.
 */
const loginIdentifierQualifierPriority: string[] = [
  AutofillTargetingRuleTypes.username,
  AutofillTargetingRuleTypes.email,
  AutofillTargetingRuleTypes.phone,
];

export default class AutofillService extends AutofillScriptGenerator implements AutofillServiceInterface {
  private openVaultItemPasswordRepromptPopout = openVaultItemPasswordRepromptPopout;
  private openPasswordRepromptPopoutDebounce?: ReturnType<typeof setTimeout>;
  private currentlyOpeningPasswordRepromptPopout = false;
  enableInlineMenuAnimation$: Observable<boolean>;
  enableNotificationAnimation$: Observable<boolean>;

  constructor(
    private cipherService: CipherService,
    private autofillSettingsService: AutofillSettingsServiceAbstraction,
    private totpService: TotpService,
    private eventCollectionService: EventCollectionService,
    private logService: LogService,
    private domainSettingsService: DomainSettingsService,
    private userVerificationService: UserVerificationService,
    private billingAccountProfileStateService: BillingAccountProfileStateService,
    private scriptInjectorService: ScriptInjectorService,
    private accountService: AccountService,
    private authService: AuthService,
    private userNotificationSettingsService: UserNotificationSettingsServiceAbstraction,
    private messageListener: MessageListener,
    private animationControlService: AnimationControlService,
    private autofillLifecycleService: AutofillLifecycleService,
  ) {
    super({ totpService, domainSettingsService, logService });
    this.enableInlineMenuAnimation$ = this.animationControlService.enableInlineMenuAnimation$;
    this.enableNotificationAnimation$ = this.animationControlService.enableNotificationAnimation$;
  }

  /**
   * Collects page details from a tab. Returns an observable that builds the results from the
   * collectPageDetailsResponse messages the tab's frames send back. When `frameId` is given, the
   * collection is scoped to that one frame — only it is asked, and only its response is admitted, so
   * a concurrent collection on another frame of the same tab cannot bleed in.
   *
   * @param tab The tab to collect page details from
   * @param frameId When set, collect only this frame; otherwise collect every frame
   */
  collectPageDetailsFromTab$(tab: chrome.tabs.Tab, frameId?: number): Observable<PageDetail[]> {
    /** Replay Subject that can be utilized when `messages$` may not emit the page details. */
    const pageDetailsFallback$ = new ReplaySubject<PageDetail[]>(1);

    const pageDetailsFromTab$ = this.messageListener
      .messages$(COLLECT_PAGE_DETAILS_RESPONSE_COMMAND)
      .pipe(
        filter(
          (message) =>
            message.sender === AutofillMessageSender.collectPageDetailsFromTabObservable &&
            message.tab?.id === tab.id &&
            (frameId === undefined || getWebExtSender(message)?.frameId === frameId),
        ),
        scan((acc: PageDetail[], message): PageDetail[] => {
          const frameId = getWebExtSender(message)?.frameId;
          return frameId === undefined
            ? acc
            : [
                ...acc,
                {
                  frameId,
                  tab: message.tab,
                  details: message.details,
                },
              ];
        }, [] as PageDetail[]),
      );

    void BrowserApi.tabSendMessage(
      tab,
      {
        tab: tab,
        command: AutofillMessageCommand.collectPageDetails,
        sender: AutofillMessageSender.collectPageDetailsFromTabObservable,
      },
      frameId !== undefined ? { frameId } : undefined,
      true,
    ).catch(() => {
      // When `tabSendMessage` throws an error the `pageDetailsFromTab$` will not emit,
      // fallback to an empty array
      pageDetailsFallback$.next([]);
    });

    // Fallback to empty array when:
    // - In Safari, `tabSendMessage` doesn't throw an error for this case.
    // - When opening the extension directly via the URL, `tabSendMessage` doesn't always respond nor throw an error in FireFox.
    //   Adding checks for the major 3 browsers here to be safe.
    const urlHasBrowserProtocol = [
      "moz-extension://",
      "chrome-extension://",
      "safari-web-extension://",
    ].some((protocol) => tab.url?.startsWith(protocol));
    if (!tab.url || urlHasBrowserProtocol) {
      pageDetailsFallback$.next([]);
    }

    // Share the pageDetailsFromTab$ observable so that multiple subscribers don't trigger multiple executions.
    const sharedPageDetailsFromTab$ = pageDetailsFromTab$.pipe(share());

    // Create a timeout observable that emits an empty array if pageDetailsFromTab$ hasn't emitted within 1 second.
    const pageDetailsTimeout$ = timer(1000).pipe(
      map(() => [] as PageDetail[]),
      takeUntil(sharedPageDetailsFromTab$),
    );

    // Merge the responses so that if pageDetailsFromTab$ emits, that value is used.
    // Otherwise, if it doesn't emit in time, the timeout observable emits an empty array.
    // Also, pageDetailsFallback$ will emit in error cases.
    return merge(sharedPageDetailsFromTab$, pageDetailsFallback$, pageDetailsTimeout$);
  }

  /**
   * Triggers on installation of the extension Handles injecting
   * content scripts into all tabs that are currently open, and
   * sets up a listener to ensure content scripts can identify
   * if the extension context has been disconnected.
   */
  async loadAutofillScriptsOnInstall() {
    void this.injectAutofillScriptsInAllTabs();

    this.autofillSettingsService.inlineMenuVisibility$
      .pipe(startWith(undefined), pairwise())
      .subscribe(([previousSetting, currentSetting]) =>
        this.handleInlineMenuVisibilitySettingsChange(previousSetting, currentSetting),
      );

    this.autofillSettingsService.showInlineMenuCards$
      .pipe(startWith(undefined), pairwise())
      .subscribe(([previousSetting, currentSetting]) =>
        this.handleInlineMenuVisibilitySettingsChange(previousSetting, currentSetting),
      );

    this.autofillSettingsService.showInlineMenuIdentities$
      .pipe(startWith(undefined), pairwise())
      .subscribe(([previousSetting, currentSetting]) =>
        this.handleInlineMenuVisibilitySettingsChange(previousSetting, currentSetting),
      );
  }

  /**
   * Triggers a complete reload of all autofill scripts on tabs open within
   * the user's browsing session. This is done by first disconnecting all
   * existing autofill content script ports, which cleans up existing object
   * instances, and then re-injecting the autofill scripts into all tabs.
   */
  async reloadAutofillScripts() {
    this.autofillLifecycleService.retireAllFrames();
    void this.injectAutofillScriptsInAllTabs();
  }

  /**
   * Injects the autofill scripts into the current tab and all frames
   * found within the tab. Temporarily, will conditionally inject
   * the refactor of the core autofill script if the feature flag
   * is enabled.
   * @param {chrome.tabs.Tab} tab
   * @param {number} frameId
   * @param {boolean} triggeringOnPageLoad
   */
  async injectAutofillScripts(
    tab: chrome.tabs.Tab,
    frameId = 0,
    triggeringOnPageLoad = true,
  ): Promise<void> {
    const tabId = tab.id;
    if (tabId === undefined) {
      return;
    }
    // Autofill user settings loaded from state can await the active account state indefinitely
    // if not guarded by an active account check (e.g. the user is logged in)
    const activeAccount = await firstValueFrom(this.accountService.activeAccount$);
    const authStatus = await firstValueFrom(this.authService.activeAccountStatus$);
    const accountIsUnlocked = authStatus === AuthenticationStatus.Unlocked;
    let autoFillOnPageLoadIsEnabled = false;

    const injectedScripts = [await this.getBootstrapAutofillContentScript(activeAccount)];

    if (activeAccount && accountIsUnlocked) {
      autoFillOnPageLoadIsEnabled = await this.getAutofillOnPageLoad();
    }

    if (triggeringOnPageLoad && autoFillOnPageLoadIsEnabled) {
      injectedScripts.push("autofiller.js");
    }

    if (!triggeringOnPageLoad) {
      await this.scriptInjectorService.inject({
        tabId,
        injectDetails: { file: "content/content-message-handler.js", runAt: "document_start" },
      });
    }

    injectedScripts.push("contextMenuHandler.js");

    for (const injectedScript of injectedScripts) {
      await this.scriptInjectorService.inject({
        tabId,
        injectDetails: {
          file: `content/${injectedScript}`,
          runAt: "document_start",
          frame: frameId,
        },
      });
    }

    // Now that this frame's scripts are injected, hand off to the lifecycle
    // service to begin monitoring it (when an account is logged in).
    await this.autofillLifecycleService.startMonitoringFrame(tab, frameId);
  }

  /**
   * Identifies the correct autofill script to inject based on whether the
   * inline menu is enabled, and whether the user has the notification bar
   * enabled.
   *
   * @param activeAccount - The active account
   */
  private async getBootstrapAutofillContentScript(
    activeAccount: ({ id: UserId | undefined } & AccountInfo) | null | undefined,
  ): Promise<string> {
    let inlineMenuVisibility: InlineMenuVisibilitySetting = AutofillOverlayVisibility.Off;

    if (activeAccount) {
      inlineMenuVisibility = await this.getInlineMenuVisibility();
    }

    const enableChangedPasswordPrompt = await firstValueFrom(
      this.userNotificationSettingsService.enableChangedPasswordPrompt$,
    );
    const enableAddedLoginPrompt = await firstValueFrom(
      this.userNotificationSettingsService.enableAddedLoginPrompt$,
    );
    const isNotificationBarEnabled = enableChangedPasswordPrompt || enableAddedLoginPrompt;

    if (!inlineMenuVisibility && !isNotificationBarEnabled) {
      return "bootstrap-autofill.js";
    }

    if (!inlineMenuVisibility && isNotificationBarEnabled) {
      return "bootstrap-autofill-overlay-notifications.js";
    }

    if (inlineMenuVisibility && !isNotificationBarEnabled) {
      return "bootstrap-autofill-overlay-menu.js";
    }

    return "bootstrap-autofill-overlay.js";
  }

  /**
   * Gets all forms with password fields and formats the data
   * for both forms and password input elements.
   * @param {AutofillPageDetails} pageDetails
   * @returns {FormData[]}
   */
  getFormsWithPasswordFields(pageDetails: AutofillPageDetails): FormData[] {
    const formData: FormData[] = [];

    const passwordFields = AutofillService.loadPasswordFields(
      pageDetails,
      true,
      true,
      false,
      true,
      undefined,
    );

    // TODO: this logic prevents multi-step account creation forms (that just start with email)
    // from being passed on to the notification bar content script - even if autofill-init.js found the form and email field.
    // ex: https://signup.live.com/
    if (passwordFields.length === 0) {
      return formData;
    }

    // Back up check for cases where there are several password fields detected,
    // but they are not all part of the form b/c of bad HTML

    // gather password fields that don't have an enclosing form
    const passwordFieldsWithoutForm = passwordFields.filter((pf) => pf.form === undefined);
    const formKeys = Object.keys(pageDetails.forms);
    const formCount = formKeys.length;

    // if we have 3 password fields and only 1 form, and there are password fields that are not within a form
    // but there is at least one password field within the form, then most likely this is a poorly built password change form
    if (passwordFields.length === 3 && formCount == 1 && passwordFieldsWithoutForm.length > 0) {
      // Only one form so get the singular form key
      const soloFormKey = formKeys[0];

      const atLeastOnePasswordFieldWithinSoloForm =
        passwordFields.filter((pf) => pf.form !== null && pf.form === soloFormKey).length > 0;

      if (atLeastOnePasswordFieldWithinSoloForm) {
        // We have a form with at least one password field,
        // so let's make an assumption that the password fields without a form are actually part of this form
        passwordFieldsWithoutForm.forEach((pf) => {
          pf.form = soloFormKey;
        });
      }
    }

    for (const formKey in pageDetails.forms) {
      // eslint-disable-next-line
      if (!pageDetails.forms.hasOwnProperty(formKey)) {
        continue;
      }

      const formPasswordFields = passwordFields.filter((pf) => formKey === pf.form);
      if (formPasswordFields.length > 0) {
        let uf = this.findUsernameField(pageDetails, formPasswordFields[0], false, false, false);
        if (uf == null) {
          // not able to find any viewable username fields. maybe there are some "hidden" ones?
          uf = this.findUsernameField(pageDetails, formPasswordFields[0], true, true, false);
        }
        formData.push({
          form: pageDetails.forms[formKey],
          password: formPasswordFields[0],
          username: uf ?? null,
          passwords: formPasswordFields,
        });
      }
    }

    return formData;
  }

  /**
   * Gets the overlay's visibility setting from the autofill settings service.
   */
  async getInlineMenuVisibility(): Promise<InlineMenuVisibilitySetting> {
    return await firstValueFrom(this.autofillSettingsService.inlineMenuVisibility$);
  }

  /**
   * Gets the setting for automatically copying TOTP upon autofill from the autofill settings service.
   */
  async getShouldAutoCopyTotp(): Promise<boolean> {
    return await firstValueFrom(this.autofillSettingsService.autoCopyTotp$);
  }

  /**
   * Gets the autofill on page load setting from the autofill settings service.
   */
  async getAutofillOnPageLoad(): Promise<boolean> {
    return await firstValueFrom(this.autofillSettingsService.autofillOnPageLoad$);
  }

  /**
   * Gets the default URI match strategy setting from the domain settings service.
   */
  async getDefaultUriMatchStrategy(): Promise<UriMatchStrategySetting> {
    return await firstValueFrom(this.domainSettingsService.resolvedDefaultUriMatchStrategy$);
  }

  /**
   * Resolves a cipher's TOTP code for clipboard copy when the caller can't rely on a successful
   * fill to produce one (e.g., a hidden TOTP input that the fill script can't target). Applies
   * the same premium/organization gate and auto-copy setting as {@link doAutoFill}.
   */
  async getTotpCopyCode(cipher: CipherView): Promise<string | undefined> {
    if (cipher.type !== CipherType.Login || !cipher.login?.totp) {
      return undefined;
    }

    if (!(await this.getShouldAutoCopyTotp())) {
      return undefined;
    }

    const activeAccount = await firstValueFrom(this.accountService.activeAccount$);
    const canAccessPremium = activeAccount?.id
      ? await firstValueFrom(
          this.billingAccountProfileStateService.hasPremiumFromAnySource$(activeAccount.id),
        )
      : false;

    if (!canAccessPremium && !cipher.organizationUseTotp) {
      return undefined;
    }

    return (await firstValueFrom(this.totpService.getCode$(cipher.login.totp))).code ?? undefined;
  }

  /**
   * Autofill a given tab with a given login item
   * @param {AutoFillOptions} options Instructions about the autofill operation, including tab and login item
   * @returns {Promise<AutoFillResult>} Whether a fill was dispatched (`didAutofill`) and the TOTP code
   * of the successfully autofilled login, if any. A no-fill is reported as `{ didAutofill: false }`
   * rather than a thrown exception.
   * @throws Rejects when an unexpected error occurs during the fill; a no-fill is not an error and
   * resolves to `{ didAutofill: false }`.
   */
  async doAutoFill(options: AutoFillOptions): Promise<AutoFillResult> {
    const tab = options.tab;
    const tabUrl = tab?.url;
    if (!tabUrl || !options.cipher || !options.pageDetails || !options.pageDetails.length) {
      return { didAutofill: false };
    }

    let totp: string | null = null;

    const activeAccount = await firstValueFrom(this.accountService.activeAccount$);
    let canAccessPremium = false;
    if (activeAccount?.id) {
      canAccessPremium = await firstValueFrom(
        this.billingAccountProfileStateService.hasPremiumFromAnySource$(activeAccount.id),
      );
    }
    const defaultUriMatch = await this.getDefaultUriMatchStrategy();

    const canUseTotp = canAccessPremium || options.cipher.organizationUseTotp;

    let didAutofill = false;
    await Promise.all(
      options.pageDetails.map(async (pd) => {
        // make sure we're still on correct tab
        if (pd.tab.id !== tab.id || pd.tab.url !== tab.url) {
          return;
        }

        // If we have a focused form, filter the page details to only include fields from that form
        const details = options.focusedFieldForm
          ? {
              ...pd.details,
              fields: pd.details.fields.filter((f) => f.form === options.focusedFieldForm),
            }
          : pd.details;

        const fillScript = await this.generateFillScript(details, {
          skipUsernameOnlyFill: options.skipUsernameOnlyFill || false,
          onlyEmptyFields: options.onlyEmptyFields || false,
          fillNewPassword: options.fillNewPassword || false,
          allowTotpAutofill: options.allowTotpAutofill || false,
          autoSubmitLogin: options.autoSubmitLogin || false,
          cipher: options.cipher,
          canAccessTotp: canUseTotp,
          tabUrl,
          defaultUriMatch: defaultUriMatch,
          focusedFieldOpid: options.focusedFieldOpid,
          inlineMenuFillType: options.inlineMenuFillType,
        });

        if (!fillScript || !fillScript.script || !fillScript.script.length) {
          return;
        }

        if (
          fillScript.untrustedIframe &&
          options.allowUntrustedIframe != undefined &&
          !options.allowUntrustedIframe
        ) {
          this.logService.info("Autofill on page load was blocked due to an untrusted iframe.");
          return;
        }

        // Add a small delay between operations
        fillScript.properties.delay_between_operations = 20;

        didAutofill = true;
        if (!options.skipLastUsed && activeAccount?.id) {
          await this.cipherService.updateLastUsedDate(options.cipher.id, activeAccount.id);
        }

        const showAnimations =
          (await firstValueFrom(this.animationControlService.enableAutofillAnimation$)) ?? true;

        void BrowserApi.tabSendMessage(
          tab,
          {
            command: options.autoSubmitLogin ? "triggerAutoSubmitLogin" : "fillForm",
            fillScript: fillScript,
            url: tab.url,
            pageDetailsUrl: pd.details.url,
            showAnimations,
          },
          { frameId: pd.frameId },
        );

        // Skip getting the TOTP code for clipboard in these cases
        if (
          options.cipher.type !== CipherType.Login ||
          totp !== null ||
          !canUseTotp ||
          !options.cipher.login?.totp
        ) {
          return;
        }

        const shouldAutoCopyTotp = await this.getShouldAutoCopyTotp();

        totp = shouldAutoCopyTotp
          ? (await firstValueFrom(this.totpService.getCode$(options.cipher.login.totp))).code
          : null;
      }),
    );

    if (didAutofill) {
      await this.eventCollectionService.collect(
        EventType.Cipher_ClientAutofilled,
        options.cipher.id,
      );
      // Map the internal `null` (no TOTP) to the outcome's optional `totp`.
      return { didAutofill: true, totp: totp ?? undefined };
    } else {
      return { didAutofill: false };
    }
  }

  /**
   * Autofill the specified tab with the next login item from the cache
   * @param {PageDetail[]} pageDetails The data scraped from the page
   * @param {chrome.tabs.Tab} tab The tab to be autofilled
   * @param {boolean} fromCommand Whether the autofill is triggered by a keyboard shortcut (`true`) or autofill on page load (`false`)
   * @param {boolean} autoSubmitLogin Whether the autofill is for an auto-submit login
   * @returns {Promise<AutoFillResult>} Whether a fill was dispatched (`didAutofill`) and the TOTP code
   * of the successfully autofilled login, if any
   */
  async doAutoFillOnTab(
    pageDetails: PageDetail[],
    tab: chrome.tabs.Tab,
    fromCommand: boolean,
    autoSubmitLogin = false,
  ): Promise<AutoFillResult> {
    let cipher: CipherView;

    const activeUserId = await firstValueFrom(
      this.accountService.activeAccount$.pipe(getOptionalUserId),
    );
    if (activeUserId == null) {
      return { didAutofill: false };
    }

    if (!tab.url) {
      return { didAutofill: false };
    }
    const tabUrl = tab.url;
    if (fromCommand) {
      cipher = await this.cipherService.getNextCipherForUrl(tabUrl, activeUserId);
    } else {
      const lastLaunchedCipher = await this.cipherService.getLastLaunchedForUrl(
        tabUrl,
        activeUserId,
        true,
      );
      const lastLaunched = lastLaunchedCipher?.localData?.lastLaunched;
      if (
        lastLaunchedCipher &&
        lastLaunched &&
        Date.now().valueOf() - lastLaunched.valueOf() < 30000
      ) {
        cipher = lastLaunchedCipher;
      } else {
        cipher = await this.cipherService.getLastUsedForUrl(tabUrl, activeUserId, true);
      }
    }

    if (cipher == null || (cipher.reprompt === CipherRepromptType.Password && !fromCommand)) {
      return { didAutofill: false };
    }

    if (await this.isPasswordRepromptRequired(cipher, tab)) {
      if (fromCommand) {
        this.cipherService.updateLastUsedIndexForUrl(tabUrl);
      }

      return { didAutofill: false };
    }

    const result = await this.doAutoFill({
      tab: tab,
      cipher: cipher,
      pageDetails: pageDetails,
      skipLastUsed: !fromCommand,
      skipUsernameOnlyFill: !fromCommand,
      onlyEmptyFields: !fromCommand,
      fillNewPassword: fromCommand,
      allowUntrustedIframe: fromCommand,
      allowTotpAutofill: fromCommand,
      autoSubmitLogin,
    });

    // Update last used index as autofill has succeeded
    if (fromCommand && result.didAutofill) {
      this.cipherService.updateLastUsedIndexForUrl(tabUrl);
    }

    return result;
  }

  /**
   * Checks if the cipher requires password reprompt and opens the password reprompt popout if necessary.
   *
   * @param cipher - The cipher to autofill
   * @param tab - The tab to autofill
   * @param action - override for default action once reprompt is completed successfully
   */
  async isPasswordRepromptRequired(
    cipher: CipherView,
    tab: chrome.tabs.Tab,
    action?: string,
  ): Promise<boolean> {
    const userHasMasterPassword = await this.userVerificationService.hasMasterPassword();
    if (cipher.reprompt === CipherRepromptType.Password && userHasMasterPassword) {
      if (!this.isDebouncingPasswordRepromptPopout()) {
        await this.openVaultItemPasswordRepromptPopout(tab, {
          cipherId: cipher.id,
          action: action ?? "autofill",
        });
      }

      return true;
    }

    return false;
  }

  /**
   * Autofill the active tab with the next cipher from the cache
   * @param {PageDetail[]} pageDetails The data scraped from the page
   * @param {boolean} fromCommand Whether the autofill is triggered by a keyboard shortcut (`true`) or autofill on page load (`false`)
   * @returns {Promise<AutoFillResult>} Whether a fill was dispatched (`didAutofill`) and the TOTP code
   * of the successfully autofilled login, if any
   */
  async doAutoFillActiveTab(
    pageDetails: PageDetail[],
    fromCommand: boolean,
    cipherType?: CipherType,
  ): Promise<AutoFillResult> {
    if (!pageDetails[0]?.details?.fields?.length) {
      return { didAutofill: false };
    }

    const tab = await this.getActiveTab();

    if (!tab || !tab.url) {
      return { didAutofill: false };
    }

    if (!cipherType || cipherType === CipherType.Login) {
      return await this.doAutoFillOnTab(pageDetails, tab, fromCommand);
    }

    let cipher: CipherView;
    let cacheKey = "";

    const activeUserId = await firstValueFrom(
      this.accountService.activeAccount$.pipe(getOptionalUserId),
    );
    if (activeUserId == null) {
      return { didAutofill: false };
    }

    if (cipherType === CipherType.Card) {
      cacheKey = "cardCiphers";
      cipher = await this.cipherService.getNextCardCipher(activeUserId);
    } else {
      cacheKey = "identityCiphers";
      cipher = await this.cipherService.getNextIdentityCipher(activeUserId);
    }

    if (!cipher || !cacheKey || (cipher.reprompt === CipherRepromptType.Password && !fromCommand)) {
      return { didAutofill: false };
    }

    if (await this.isPasswordRepromptRequired(cipher, tab)) {
      if (fromCommand) {
        this.cipherService.updateLastUsedIndexForUrl(cacheKey);
      }

      return { didAutofill: false };
    }

    const result = await this.doAutoFill({
      tab: tab,
      cipher: cipher,
      pageDetails: pageDetails,
      skipLastUsed: !fromCommand,
      skipUsernameOnlyFill: !fromCommand,
      onlyEmptyFields: !fromCommand,
      fillNewPassword: false,
      allowUntrustedIframe: fromCommand,
      allowTotpAutofill: false,
    });

    if (fromCommand && result.didAutofill) {
      this.cipherService.updateLastUsedIndexForUrl(cacheKey);
    }

    return result;
  }

  /**
   * Activates the autofill on page load org policy.
   */
  async setAutoFillOnPageLoadOrgPolicy(): Promise<void> {
    const autofillOnPageLoadOrgPolicy = await firstValueFrom(
      this.autofillSettingsService.activateAutofillOnPageLoadFromPolicy$,
    );

    if (autofillOnPageLoadOrgPolicy) {
      await this.autofillSettingsService.setAutofillOnPageLoad(true);
    }
  }

  /**
   * Gets the active tab from the current window.
   * Throws an error if no tab is found.
   * @returns {Promise<chrome.tabs.Tab>}
   * @private
   */
  private async getActiveTab(): Promise<chrome.tabs.Tab> {
    const tab = await BrowserApi.getTabFromCurrentWindow();
    if (!tab) {
      throw new Error("No tab found.");
    }

    return tab;
  }

  /**
   * Handles debouncing the opening of the master password reprompt popout.
   */
  private isDebouncingPasswordRepromptPopout() {
    if (this.currentlyOpeningPasswordRepromptPopout) {
      return true;
    }

    this.currentlyOpeningPasswordRepromptPopout = true;
    clearTimeout(this.openPasswordRepromptPopoutDebounce);

    this.openPasswordRepromptPopoutDebounce = setTimeout(() => {
      this.currentlyOpeningPasswordRepromptPopout = false;
    }, 100);

    return false;
  }

  /**
   * Queries all open tabs in the user's browsing session
   * and injects the autofill scripts into the page.
   */
  private async injectAutofillScriptsInAllTabs() {
    const tabs = await BrowserApi.tabsQuery({});
    for (let index = 0; index < tabs.length; index++) {
      const tab = tabs[index];
      if (tab?.id && tab.url?.startsWith("http")) {
        const frames = await BrowserApi.getAllFrameDetails(tab.id);
        if (frames) {
          frames.forEach((frame) => this.injectAutofillScripts(tab, frame.frameId, false));
        }
      }
    }
  }

  /**
   * Updates the autofill inline menu visibility settings in all active tabs
   * when the inlineMenuVisibility, showInlineMenuCards, or showInlineMenuIdentities
   * observables are updated.
   *
   * @param oldSettingValue - The previous setting value
   * @param newSettingValue - The current setting value
   */
  private async handleInlineMenuVisibilitySettingsChange(
    oldSettingValue: InlineMenuVisibilitySetting | boolean | undefined,
    newSettingValue: InlineMenuVisibilitySetting | boolean | undefined,
  ) {
    if (oldSettingValue == null || newSettingValue == null || oldSettingValue === newSettingValue) {
      return;
    }

    const isInlineMenuVisibilitySubSetting =
      typeof oldSettingValue === "boolean" || typeof newSettingValue === "boolean";
    const inlineMenuPreviouslyDisabled = oldSettingValue === AutofillOverlayVisibility.Off;
    const inlineMenuCurrentlyDisabled = newSettingValue === AutofillOverlayVisibility.Off;
    if (
      !isInlineMenuVisibilitySubSetting &&
      !inlineMenuPreviouslyDisabled &&
      !inlineMenuCurrentlyDisabled
    ) {
      return;
    }

    await this.reloadAutofillScripts();
  }
}
