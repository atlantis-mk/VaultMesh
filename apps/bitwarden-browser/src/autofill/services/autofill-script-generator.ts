import { firstValueFrom, of } from "rxjs";
import { AutofillTargetingRuleTypes, CardExpiryDateDelimiters, FormPurposeCategories } from "@bitwarden/common/autofill/constants";
import type { DomainSettingsService } from "@bitwarden/common/autofill/services/domain-settings.service";
import { normalizeExpiryYearFormat } from "@bitwarden/common/autofill/utils";
import { UriMatchStrategy } from "@bitwarden/common/models/domain/domain-service";
import type { TotpService } from "@bitwarden/common/vault/abstractions/totp.service";
import type { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import { FieldType, CipherType } from "@bitwarden/common/vault/enums";
import { CardView } from "@bitwarden/common/vault/models/view/card.view";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { FieldView } from "@bitwarden/common/vault/models/view/field.view";
import { IdentityView } from "@bitwarden/common/vault/models/view/identity.view";
import { InlineMenuFillTypes, type InlineMenuFillType } from "../enums/autofill-overlay.enum";
import AutofillField from "../models/autofill-field";
import AutofillPageDetails from "../models/autofill-page-details";
import AutofillScript from "../models/autofill-script";
import { fieldContainsKeyword, isNonLoginUsernameField } from "../utils/qualification";
import { GenerateFillScriptOptions } from "./abstractions/autofill.service";
import { AutoFillConstants, CardExpiryDateFormat, CreditCardAutoFillConstants, IdentityAutoFillConstants, SshKeyAutoFillConstants } from "./autofill-constants";

const loginIdentifierQualifierPriority: string[] = [
  AutofillTargetingRuleTypes.username, AutofillTargetingRuleTypes.email, AutofillTargetingRuleTypes.phone,
];

/** Original Bitwarden script generator, separated from account/storage/sync lifecycle.
 * With no local dependencies it only accepts remote value-less planning.
 */
export class AutofillScriptGenerator {
  static searchFieldNamesSet = new Set(AutoFillConstants.SearchFieldNames);
  constructor(private readonly planningDependencies?: {
    logService: Pick<LogService, "error">;
    totpService: Pick<TotpService, "getCode$">;
    domainSettingsService: Pick<DomainSettingsService, "resolvedEnableFillAssist$" | "getUrlEquivalentDomains">;
  }) {}
  private requireLocalTotp() {
    if (!this.planningDependencies) throw new Error("TOTP generation belongs to the desktop broker.");
    return this.planningDependencies.totpService;
  }
  /**
   * Generates the autofill script for the specified page details and cipher.
   * @param {AutofillPageDetails} pageDetails
   * @param {GenerateFillScriptOptions} options
   * @returns {Promise<AutofillScript | null>}
   * @private
   */
  public async generateFillScript(
    pageDetails: AutofillPageDetails,
    options: GenerateFillScriptOptions,
  ): Promise<AutofillScript | null> {
    if (!this.planningDependencies && !options.remoteTotpPlanning) {
      throw new Error("Remote planning requires value-less TOTP planning mode.");
    }
    if (!pageDetails || !options.cipher) {
      return null;
    }

    // Check if page details contain targeted fields from targeting rules
    // This operation is mutually-exclusive from heuristic data-gathering
    const pageHasTargetedFields = pageDetails.fields.some(({ targeted }) => targeted === true);

    if (pageHasTargetedFields) {
      const fillAssistEnabled = await firstValueFrom(
        this.planningDependencies?.domainSettingsService.resolvedEnableFillAssist$ ?? of(false),
      );

      // We could alternatively retrigger gathering page details with the
      // heuristic strategy, but this code path is mostly defensive and not
      // expected to be hit often, since the entrypoints for this workflow
      // are also expected to be gated.
      if (!fillAssistEnabled) {
        return null;
      }
      return this.generateTargetedFillScript(pageDetails, options);
    }

    const fillScript = new AutofillScript();
    const filledFields: { [id: string]: AutofillField } = {};
    const fields = options.cipher.fields;

    if (fields && fields.length) {
      const fieldNames: string[] = [];

      fields.forEach((f) => {
        if (f.name != null && AutofillScriptGenerator.hasValue(f.name)) {
          fieldNames.push(f.name.toLowerCase());
        }
      });

      pageDetails.fields.forEach((field) => {
        const fieldOpid = field.opid;
        if (fieldOpid == null) {
          return;
        }
        if (Object.prototype.hasOwnProperty.call(filledFields, fieldOpid)) {
          return;
        }

        if (!field.viewable && field.tagName !== "span") {
          return;
        }

        // Check if the input is an untyped/mistyped search input
        if (AutofillScriptGenerator.isSearchField(field)) {
          return;
        }

        const matchingIndex = this.findMatchingFieldIndex(field, fieldNames);
        if (matchingIndex > -1) {
          const matchingField: FieldView = fields[matchingIndex];
          let val: string;
          if (matchingField.type === FieldType.Linked) {
            if (matchingField.linkedId == null) {
              return;
            }
            // Assumption: Linked Field is not being used to autofill a boolean value
            val = options.cipher.linkedFieldValue(matchingField.linkedId) as string;
          } else {
            const rawVal = matchingField.value;
            if (rawVal == null) {
              if (matchingField.type === FieldType.Boolean) {
                val = "false";
              } else {
                return;
              }
            } else {
              val = rawVal;
            }
          }

          filledFields[fieldOpid] = field;
          AutofillScriptGenerator.fillByOpid(fillScript, field, val);
        }
      });
    }

    let result: AutofillScript | null = null;
    switch (options.cipher.type) {
      case CipherType.Login:
        result = await this.generateLoginFillScript(fillScript, pageDetails, filledFields, options);
        break;
      case CipherType.Card:
        result = await this.generateCardFillScript(fillScript, pageDetails, filledFields, options);
        break;
      case CipherType.Identity:
        result = await this.generateIdentityFillScript(
          fillScript,
          pageDetails,
          filledFields,
          options,
        );
        break;
      case CipherType.SshKey:
        result = this.generateSshKeyFillScript(fillScript, pageDetails, filledFields, options);
        break;
      default:
        return null;
    }

    return result;
  }

  /**
   * Generates fill script actions for targeted fields, mapping cipher values
   * directly to field types identified by targeting rules. Reuses the standard
   * fill_by_opid actions since targeted elements are cached with synthetic opids.
   */
  protected async generateTargetedFillScript(
    pageDetails: AutofillPageDetails,
    options: GenerateFillScriptOptions,
  ): Promise<AutofillScript | null> {
    const fillScript = new AutofillScript();
    const cipher = options.cipher;
    const isPasswordGeneration =
      options.inlineMenuFillType === InlineMenuFillTypes.PasswordGeneration;

    fillScript.savedUrls =
      cipher.login?.uris
        ?.filter((u) => u.match != UriMatchStrategy.Never && u.uri != null)
        .map((u) => u.uri!) ?? [];

    // Note, targeted fields intentionally skip the untrusted iframe check. The
    // presence of targeting rules represents explicit expectations of the target

    // For a Login cipher, `login.username` fills only the single highest-priority
    // identifier field present in an `account-login` form (see the priority list).
    const isLoginCipher = cipher.type === CipherType.Login;
    const loginIdentifierQualifier = isLoginCipher
      ? this.resolveLoginIdentifierQualifier(pageDetails)
      : null;

    for (const field of pageDetails.fields) {
      if (!field.targeted || !field.fieldQualifier) {
        continue;
      }

      let value: string | null;
      if (isPasswordGeneration && field.fieldQualifier === AutofillTargetingRuleTypes.newPassword) {
        // The Login cipher is a transient representation of the generated password
        // value, so the usual logic skipping new password fills does not apply here
        value = cipher.login?.password ?? null;
      } else if (
        isLoginCipher &&
        field.formCategory === FormPurposeCategories.AccountLogin &&
        loginIdentifierQualifierPriority.includes(field.fieldQualifier)
      ) {
        // The login identifier fills the winning identifier field only; sibling
        // identifier fields are skipped. This presumes a _login_ form will not require
        // more than one of a `loginIdentifierQualifierPriority` (e.g. only one of
        // username, email, or phone number).
        value =
          field.fieldQualifier === loginIdentifierQualifier
            ? (cipher.login?.username ?? null)
            : null;
      } else {
        value = this.getValueForTargetedFieldType(field.fieldQualifier, cipher);
      }

      if (!value) {
        continue;
      }

      AutofillScriptGenerator.fillByOpid(fillScript, field, value);
    }

    if (!fillScript.script.length) {
      return null;
    }

    return fillScript;
  }

  /**
   * Determines which identifier field a Login cipher's `login.username` should
   * fill, given the targeted fields present on `account-login` forms. Returns
   * the highest-priority present qualifier (username > email > phone), or null
   * when none are present.
   */
  protected resolveLoginIdentifierQualifier(pageDetails: AutofillPageDetails): string | null {
    const presentIdentifierQualifiers = new Set(
      pageDetails.fields
        .filter(
          (field) =>
            field.targeted &&
            field.formCategory === FormPurposeCategories.AccountLogin &&
            field.fieldQualifier != null,
        )
        .map((field) => field.fieldQualifier as string),
    );

    return (
      loginIdentifierQualifierPriority.find((qualifier) =>
        presentIdentifierQualifiers.has(qualifier),
      ) ?? null
    );
  }

  /**
   * Maps a targeting rule field type to the corresponding cipher value.
   */
  protected getValueForTargetedFieldType(fieldType: string, cipher: CipherView): string | null {
    // Login fields
    if (fieldType === AutofillTargetingRuleTypes.username) {
      return cipher.login?.username ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.password) {
      return cipher.login?.password ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.newPassword) {
      return null;
    }

    // Card fields
    if (fieldType === AutofillTargetingRuleTypes.cardholderName) {
      return cipher.card?.cardholderName ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.cardNumber) {
      return cipher.card?.number ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.cardExpirationMonth) {
      return cipher.card?.expMonth ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.cardExpirationYear) {
      return cipher.card?.expYear ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.cardExpirationDate) {
      // FIXME combined expiry format is presumed and should be informed by
      // the target format expectation
      return cipher.card?.expMonth && cipher.card?.expYear
        ? `${cipher.card.expMonth}/${cipher.card.expYear}`
        : null;
    }
    if (fieldType === AutofillTargetingRuleTypes.cardCvv) {
      return cipher.card?.code ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.cardType) {
      return cipher.card?.brand ?? null;
    }

    // Identity fields
    if (fieldType === AutofillTargetingRuleTypes.honorificPrefix) {
      return cipher.identity?.title ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.firstName) {
      return cipher.identity?.firstName ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.middleName) {
      return cipher.identity?.middleName ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.lastName) {
      return cipher.identity?.lastName ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.fullName) {
      return cipher.identity?.fullName ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.streetAddress) {
      return cipher.identity?.fullAddress ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.addressLine1) {
      return cipher.identity?.address1 ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.addressLine2) {
      return cipher.identity?.address2 ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.addressLine3) {
      return cipher.identity?.address3 ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.addressLevel2) {
      return cipher.identity?.city ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.addressLevel1) {
      return cipher.identity?.state ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.postalCode) {
      return cipher.identity?.postalCode ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.country) {
      return cipher.identity?.country ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.organization) {
      return cipher.identity?.company ?? null;
    }
    if (fieldType === AutofillTargetingRuleTypes.phone) {
      return cipher.identity?.phone ?? null;
    }
    // FIXME phone sub-parts (phoneCountryCode, phoneAreaCode, phoneLocal,
    // phoneExtension) can be derived by parsing cipher.identity?.phone
    if (fieldType === AutofillTargetingRuleTypes.email) {
      return cipher.identity?.email ?? null;
    }

    return null;
  }

  /**
   * Generates the autofill script for the specified page details and login cipher item.
   * @param {AutofillScript} fillScript
   * @param {AutofillPageDetails} pageDetails
   * @param {{[p: string]: AutofillField}} filledFields
   * @param {GenerateFillScriptOptions} options
   * @returns {Promise<AutofillScript | null>}
   * @private
   */
  protected async generateLoginFillScript(
    fillScript: AutofillScript,
    pageDetails: AutofillPageDetails,
    filledFields: { [id: string]: AutofillField },
    options: GenerateFillScriptOptions,
  ): Promise<AutofillScript | null> {
    if (!options.cipher.login) {
      return null;
    }

    const passwords: AutofillField[] = [];
    const usernames = new Map<string, AutofillField>();
    const totps: AutofillField[] = [];
    let pf: AutofillField | null = null;
    let username: AutofillField | null = null;
    let totp: AutofillField | null = null;
    const login = options.cipher.login;
    const totpToFill = options.allowTotpAutofill && options.canAccessTotp ? login?.totp : undefined;
    const loginURIs = login?.uris ?? [];
    fillScript.savedUrls = loginURIs.reduce<string[]>((acc, savedURI) => {
      if (savedURI.match != UriMatchStrategy.Never && savedURI.uri != null) {
        acc.push(savedURI.uri);
      }
      return acc;
    }, []);

    fillScript.untrustedIframe = await this.inUntrustedIframe(pageDetails.url, options);

    const passwordFields = AutofillScriptGenerator.loadPasswordFields(
      pageDetails,
      false,
      false,
      options.onlyEmptyFields,
      options.fillNewPassword,
      options.inlineMenuFillType,
    );

    const loginPasswordFields: AutofillField[] = [];
    const registrationPasswordFields: AutofillField[] = [];

    passwordFields.forEach((passField) => {
      if (this.isRegistrationPasswordField(pageDetails, passField)) {
        registrationPasswordFields.push(passField);
      } else {
        loginPasswordFields.push(passField);
      }
    });

    // Prefer login fields over registration fields
    const prioritizedPasswordFields =
      loginPasswordFields.length > 0 ? loginPasswordFields : registrationPasswordFields;

    const focusedField = options.focusedFieldOpid
      ? pageDetails.fields.find((f) => f.opid === options.focusedFieldOpid)
      : undefined;
    const focusedForm = focusedField?.form;

    const isFocusedTotpField =
      focusedField &&
      options.allowTotpAutofill &&
      (focusedField.type === "text" ||
        focusedField.type === "number" ||
        focusedField.type === "tel") &&
      (fieldContainsKeyword(focusedField, [
        ...AutoFillConstants.TotpFieldNames,
        ...AutoFillConstants.AmbiguousTotpFieldNames,
      ]) ||
        focusedField.autoCompleteType === "one-time-code") &&
      !fieldContainsKeyword(focusedField, [...AutoFillConstants.RecoveryCodeFieldNames]);

    const focusedUsernameField =
      focusedField &&
      !isFocusedTotpField &&
      login.username &&
      (focusedField.type === "text" ||
        focusedField.type === "email" ||
        focusedField.type === "tel") &&
      focusedField;

    const passwordMatchesFocused = (pf: AutofillField): boolean =>
      !focusedField
        ? true
        : focusedForm != null
          ? pf.form === focusedForm
          : !!(
              focusedUsernameField &&
              pf.form == null &&
              this.findUsernameField(pageDetails, pf, false, false, true)?.opid ===
                focusedUsernameField.opid
            );

    const getUsernameForPassword = (
      pf: AutofillField,
      withoutForm: boolean,
    ): AutofillField | null => {
      // use focused username if it matches this password, otherwise fall back to finding username field before password
      if (focusedUsernameField && passwordMatchesFocused(pf)) {
        return focusedUsernameField;
      }
      return this.findUsernameField(pageDetails, pf, false, false, withoutForm);
    };

    if (
      focusedUsernameField &&
      focusedUsernameField.opid != null &&
      !prioritizedPasswordFields.some(passwordMatchesFocused)
    ) {
      if (!Object.prototype.hasOwnProperty.call(filledFields, focusedUsernameField.opid)) {
        filledFields[focusedUsernameField.opid] = focusedUsernameField;
        const usernameVal = login.username;
        if (usernameVal != null) {
          AutofillScriptGenerator.fillByOpid(fillScript, focusedUsernameField, usernameVal);
        }
        if (options.autoSubmitLogin && focusedUsernameField.form) {
          fillScript.autosubmit = [focusedUsernameField.form];
        }
        return AutofillScriptGenerator.setFillScriptForFocus(
          { [focusedUsernameField.opid]: focusedUsernameField },
          fillScript,
        );
      }
    }

    const pageHasNoFormMetadata =
      pageDetails.forms == null || Object.keys(pageDetails.forms).length === 0;

    prioritizedPasswordFields.forEach((passField) => {
      if (focusedField && !passwordMatchesFocused(passField)) {
        return;
      }

      pf = passField;
      passwords.push(pf);

      if (login.username) {
        username = getUsernameForPassword(pf, pageHasNoFormMetadata);
        if (username?.opid != null) {
          usernames.set(username.opid, username);
        }
      }

      if (totpToFill) {
        totp =
          isFocusedTotpField && passwordMatchesFocused(passField)
            ? focusedField
            : this.findTotpField(pageDetails, pf, false, false, pageHasNoFormMetadata);
        if (totp) {
          totps.push(totp);
        }
      }
    });

    if (passwordFields.length && !passwords.length) {
      // in the event that password fields exist but weren't processed within form elements.
      const isPasswordGeneration =
        options.inlineMenuFillType === InlineMenuFillTypes.PasswordGeneration;
      const isCurrentPasswordUpdate =
        options.inlineMenuFillType === InlineMenuFillTypes.CurrentPasswordUpdate;

      // For password generation or current password update, include all password fields from the same form
      // This ensures we have access to all fields regardless of their login/registration classification
      if ((isPasswordGeneration || isCurrentPasswordUpdate) && focusedField) {
        // Add all password fields from the same form as the focused field
        const focusedFieldForm = focusedField.form;

        // Check both login and registration fields to ensure we get all password fields
        const allPasswordFields = [...loginPasswordFields, ...registrationPasswordFields];
        allPasswordFields.forEach((passField) => {
          if (passField.form === focusedFieldForm) {
            passwords.push(passField);
          }
        });
      }

      // If we didn't add any passwords above (either not password generation/update or no matching fields),
      // select matching password if focused, otherwise first in prioritized list.
      if (!passwords.length) {
        const passwordFieldToUse = focusedField
          ? prioritizedPasswordFields.find(passwordMatchesFocused) || prioritizedPasswordFields[0]
          : prioritizedPasswordFields[0];

        if (passwordFieldToUse) {
          passwords.push(passwordFieldToUse);
        }
      }

      // Handle username and TOTP for the first password field
      const firstPasswordField = passwords[0];
      if (firstPasswordField) {
        if (login.username && firstPasswordField.elementNumber > 0) {
          username = getUsernameForPassword(firstPasswordField, true);
          if (username?.opid != null) {
            usernames.set(username.opid, username);
          }
        }

        if (totpToFill && firstPasswordField.elementNumber > 0) {
          totp =
            isFocusedTotpField && passwordMatchesFocused(firstPasswordField)
              ? focusedField
              : this.findTotpField(pageDetails, firstPasswordField, false, false, true);
          if (totp) {
            totps.push(totp);
          }
        }
      }
    }

    if (!passwordFields.length) {
      // If there are no passwords, username or TOTP fields may be present.
      // username and TOTP fields are mutually exclusive
      pageDetails.fields.forEach((field) => {
        if (!field.viewable) {
          return;
        }

        const isTotpCandidate =
          options.allowTotpAutofill &&
          ["number", "tel", "text"].some((t) => t === field.type) &&
          !fieldContainsKeyword(field, [...AutoFillConstants.RecoveryCodeFieldNames]);

        const isTotpField =
          isTotpCandidate &&
          (fieldContainsKeyword(field, AutoFillConstants.TotpFieldNames) ||
            field.autoCompleteType === "one-time-code");

        const maybeTotpField =
          isTotpCandidate && fieldContainsKeyword(field, AutoFillConstants.AmbiguousTotpFieldNames);

        const isUsernameField =
          !options.skipUsernameOnlyFill &&
          ["email", "tel", "text"].some((t) => t === field.type) &&
          fieldContainsKeyword(field, AutoFillConstants.UsernameFieldNames) &&
          !isNonLoginUsernameField(field, pageDetails);

        // Reliable TOTP signals win unconditionally; username wins over ambiguous TOTP signals.
        switch (true) {
          case isTotpField:
            totps.push(field);
            return;
          case isUsernameField:
            usernames.set(field.opid, field);
            return;
          case maybeTotpField:
            totps.push(field);
            return;
          default:
            return;
        }
      });
    }

    const formElementsSet = new Set<string>();
    const usernamesToFill = focusedUsernameField ? [focusedUsernameField] : [...usernames.values()];

    usernamesToFill.forEach((u) => {
      if (u.opid == null) {
        return;
      }
      const uOpid = u.opid;
      if (Object.prototype.hasOwnProperty.call(filledFields, uOpid)) {
        return;
      }

      filledFields[uOpid] = u;
      const usernameVal = login.username;
      if (usernameVal != null) {
        AutofillScriptGenerator.fillByOpid(fillScript, u, usernameVal);
      }
      if (u.form != null) {
        formElementsSet.add(u.form);
      }
    });

    passwords.forEach((p) => {
      if (p.opid == null) {
        return;
      }
      const pOpid = p.opid;
      // eslint-disable-next-line
      if (filledFields.hasOwnProperty(pOpid)) {
        return;
      }

      filledFields[pOpid] = p;
      if (login.password != null) {
        AutofillScriptGenerator.fillByOpid(fillScript, p, login.password);
      }
      if (p.form != null) {
        formElementsSet.add(p.form);
      }
    });

    if (options.autoSubmitLogin && formElementsSet.size) {
      fillScript.autosubmit = Array.from(formElementsSet);
    }

    if (typeof totpToFill === "string") {
      await Promise.all(
        totps.map(async (t, i) => {
          if (t.opid == null) {
            return;
          }

          if (Object.prototype.hasOwnProperty.call(filledFields, t.opid)) {
            return;
          }

          filledFields[t.opid] = t;

          const totpValue = options.remoteTotpPlanning
            ? "01234567".slice(0, options.remoteTotpLength ?? 6)
            : (await firstValueFrom(this.requireLocalTotp().getCode$(totpToFill))).code;
          if (totpValue == null) {
            return;
          }
          const totpChar = totpValue.length === totps.length ? totpValue.charAt(i) : totpValue;
          AutofillScriptGenerator.fillByOpid(fillScript, t, totpChar);
        }),
      );
    }

    fillScript = AutofillScriptGenerator.setFillScriptForFocus(filledFields, fillScript);
    return fillScript;
  }

  /**
   * Generates the autofill script for the specified page details and credit card cipher item.
   * @param {AutofillScript} fillScript
   * @param {AutofillPageDetails} pageDetails
   * @param {{[p: string]: AutofillField}} filledFields
   * @param {GenerateFillScriptOptions} options
   * @returns {AutofillScript|null}
   * @private
   */
  protected async generateCardFillScript(
    fillScript: AutofillScript,
    pageDetails: AutofillPageDetails,
    filledFields: { [id: string]: AutofillField },
    options: GenerateFillScriptOptions,
  ): Promise<AutofillScript | null> {
    if (!options.cipher.card) {
      return null;
    }

    const fillFields: { [id: string]: AutofillField } = {};

    pageDetails.fields.forEach((f) => {
      if (AutofillScriptGenerator.isExcludedFieldType(f, AutoFillConstants.ExcludedAutofillTypes)) {
        return;
      }

      for (let i = 0; i < CreditCardAutoFillConstants.CardAttributes.length; i++) {
        const attr = CreditCardAutoFillConstants.CardAttributes[i];
        // eslint-disable-next-line
        if (!f.hasOwnProperty(attr) || !f[attr] || !f.viewable) {
          continue;
        }

        // ref https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofill
        // ref https://developers.google.com/web/fundamentals/design-and-ux/input/forms/
        if (
          !fillFields.cardholderName &&
          AutofillScriptGenerator.isFieldMatch(
            f[attr],
            CreditCardAutoFillConstants.CardHolderFieldNames,
            CreditCardAutoFillConstants.CardHolderFieldNameValues,
          )
        ) {
          fillFields.cardholderName = f;
          break;
        } else if (
          !fillFields.number &&
          AutofillScriptGenerator.isFieldMatch(
            f[attr],
            CreditCardAutoFillConstants.CardNumberFieldNames,
            CreditCardAutoFillConstants.CardNumberFieldNameValues,
          )
        ) {
          fillFields.number = f;
          break;
        } else if (
          !fillFields.exp &&
          AutofillScriptGenerator.isFieldMatch(
            f[attr],
            CreditCardAutoFillConstants.CardExpiryFieldNames,
            CreditCardAutoFillConstants.CardExpiryFieldNameValues,
          )
        ) {
          fillFields.exp = f;
          break;
        } else if (
          !fillFields.expMonth &&
          AutofillScriptGenerator.isFieldMatch(f[attr], CreditCardAutoFillConstants.ExpiryMonthFieldNames)
        ) {
          fillFields.expMonth = f;
          break;
        } else if (
          !fillFields.expYear &&
          AutofillScriptGenerator.isFieldMatch(f[attr], CreditCardAutoFillConstants.ExpiryYearFieldNames)
        ) {
          fillFields.expYear = f;
          break;
        } else if (
          !fillFields.code &&
          AutofillScriptGenerator.isFieldMatch(f[attr], CreditCardAutoFillConstants.CVVFieldNames)
        ) {
          fillFields.code = f;
          break;
        } else if (
          !fillFields.brand &&
          AutofillScriptGenerator.isFieldMatch(f[attr], CreditCardAutoFillConstants.CardBrandFieldNames)
        ) {
          fillFields.brand = f;
          break;
        }
      }
    });

    if (options.remoteItemPlanning) {
      for (const [source, field] of Object.entries(fillFields)) {
        AutofillScriptGenerator.fillByOpid(fillScript, field, `card:${source}`);
      }
      return fillScript;
    }
    const card = options.cipher.card;
    this.makeScriptAction(fillScript, card, fillFields, filledFields, "cardholderName");
    this.makeScriptAction(fillScript, card, fillFields, filledFields, "number");
    this.makeScriptAction(fillScript, card, fillFields, filledFields, "code");
    this.makeScriptAction(fillScript, card, fillFields, filledFields, "brand");

    // There is an expiration month field and the cipher has an expiration month value
    if (fillFields.expMonth && card.expMonth != null && AutofillScriptGenerator.hasValue(card.expMonth)) {
      let expMonth: string = card.expMonth;

      if (fillFields.expMonth.selectInfo && fillFields.expMonth.selectInfo.options) {
        let index: number | null = null;
        const siOptions = fillFields.expMonth.selectInfo.options;
        if (siOptions.length === 12) {
          index = parseInt(card.expMonth, 10) - 1;
        } else if (siOptions.length === 13) {
          if (
            siOptions[0][0] != null &&
            siOptions[0][0] !== "" &&
            (siOptions[12][0] == null || siOptions[12][0] === "")
          ) {
            index = parseInt(card.expMonth, 10) - 1;
          } else {
            index = parseInt(card.expMonth, 10);
          }
        }

        if (index != null) {
          const option = siOptions[index];
          if (option.length > 1) {
            expMonth = option[1];
          }
        }
      } else if (
        (this.fieldAttrsContain(fillFields.expMonth, "mm") ||
          fillFields.expMonth.maxLength === 2) &&
        expMonth.length === 1
      ) {
        expMonth = "0" + expMonth;
      }

      if (fillFields.expMonth.opid != null) {
        filledFields[fillFields.expMonth.opid] = fillFields.expMonth;
        AutofillScriptGenerator.fillByOpid(fillScript, fillFields.expMonth, expMonth);
      }
    }

    // There is an expiration year field and the cipher has an expiration year value
    if (fillFields.expYear && card.expYear != null && AutofillScriptGenerator.hasValue(card.expYear)) {
      let expYear: string = card.expYear;
      if (fillFields.expYear.selectInfo && fillFields.expYear.selectInfo.options) {
        for (let i = 0; i < fillFields.expYear.selectInfo.options.length; i++) {
          const o: [string, string] = fillFields.expYear.selectInfo.options[i];
          if (o[0] === card.expYear || o[1] === card.expYear) {
            expYear = o[1];
            break;
          }
          if (
            o[1].length === 2 &&
            card.expYear.length === 4 &&
            o[1] === card.expYear.substring(2)
          ) {
            expYear = o[1];
            break;
          }
          const colonIndex = o[1].indexOf(":");
          if (colonIndex > -1 && o[1].length > colonIndex + 1) {
            const val = o[1].substring(colonIndex + 2);
            if (val.trim() !== "" && val === card.expYear) {
              expYear = o[1];
              break;
            }
          }
        }
      } else if (
        this.fieldAttrsContain(fillFields.expYear, "yyyy") ||
        fillFields.expYear.maxLength === 4
      ) {
        if (expYear.length === 2) {
          const normalized = normalizeExpiryYearFormat(expYear);
          if (normalized != null) {
            expYear = normalized;
          }
        }
      } else if (
        this.fieldAttrsContain(fillFields.expYear, "yy") ||
        fillFields.expYear.maxLength === 2
      ) {
        if (expYear.length === 4) {
          expYear = expYear.substring(2);
        }
      }

      if (fillFields.expYear.opid != null) {
        filledFields[fillFields.expYear.opid] = fillFields.expYear;
        AutofillScriptGenerator.fillByOpid(fillScript, fillFields.expYear, expYear);
      }
    }

    // There is a single expiry date field (combined values) and the cipher has both expiration month and year
    if (
      fillFields.exp &&
      card.expMonth != null &&
      AutofillScriptGenerator.hasValue(card.expMonth) &&
      card.expYear != null &&
      AutofillScriptGenerator.hasValue(card.expYear)
    ) {
      const combinedExpiryFillValue = this.generateCombinedExpiryValue(card, fillFields.exp);

      if (combinedExpiryFillValue != null) {
        this.makeScriptActionWithValue(
          fillScript,
          combinedExpiryFillValue,
          fillFields.exp,
          filledFields,
        );
      }
    }

    return fillScript;
  }

  /**
   * Determines whether an iframe is potentially dangerous ("untrusted") to autofill
   * @param {string} pageUrl The url of the page/iframe, usually from AutofillPageDetails
   * @param {GenerateFillScriptOptions} options The GenerateFillScript options
   * @returns {boolean} `true` if the iframe is untrusted and a warning should be shown, `false` otherwise
   * @private
   */
  protected async inUntrustedIframe(
    pageUrl: string,
    options: GenerateFillScriptOptions,
  ): Promise<boolean> {
    // If the pageUrl (from the content script) matches the tabUrl (from the sender tab), we are not in an iframe
    // This also avoids a false positive if no URI is saved and the user triggers autofill anyway
    if (pageUrl === options.tabUrl) {
      return false;
    }

    // Check the pageUrl against cipher URIs using the configured match detection.
    // Remember: if we are in this function, the tabUrl already matches a saved URI for the login.
    // We need to verify the pageUrl also matches.
    const equivalentDomains = await firstValueFrom(
      this.planningDependencies?.domainSettingsService.getUrlEquivalentDomains(pageUrl) ?? of(new Set<string>()),
    );
    const matchesUri = options.cipher.login.matchesUri(
      pageUrl,
      equivalentDomains,
      options.defaultUriMatch,
    );
    return !matchesUri;
  }

  /**
   * Used when handling autofill on credit card fields. Determines whether
   * the field has an attribute that matches the given value.
   * @param {AutofillField} field
   * @param {string} containsValue
   * @returns {boolean}
   * @private
   */
  protected fieldAttrsContain(field: AutofillField, containsValue: string): boolean {
    if (!field) {
      return false;
    }

    let doesContainValue = false;
    CreditCardAutoFillConstants.CardAttributesExtended.forEach((attributeName) => {
      if (doesContainValue || !field[attributeName]) {
        return;
      }

      let fieldValue = field[attributeName];
      fieldValue = fieldValue.replace(/ /g, "").toLowerCase();
      doesContainValue = fieldValue.indexOf(containsValue) > -1;
    });

    return doesContainValue;
  }

  /**
   * Returns a string value representation of the combined card expiration month and year values
   * in a format matching discovered guidance within the field attributes (typically provided for users).
   *
   * @param {CardView} cardCipher
   * @param {AutofillField} field
   */
  protected generateCombinedExpiryValue(cardCipher: CardView, field: AutofillField): string | null {
    /*
      Some expectations of the passed stored card cipher view:

      - At the time of writing, the stored card expiry year value (`expYear`)
        can be any arbitrary string (no format validation). We may attempt some format
        normalization here, but expect the user to have entered a string of integers
        with a length of 2 or 4

      - the `expiration` property cannot be used for autofill as it is an opinionated
        format

      - `expMonth` a stringified integer stored with no zero-padding and is not
        zero-indexed (e.g. January is "1", not "01" or 0)
    */

    // Expiry format options
    let useMonthPadding = true;
    let useYearFull = false;
    let delimiter = "/";
    let orderByYear = false;

    // Because users are allowed to store truncated years, we need to make assumptions
    // about the full year format when called for
    const currentCentury = `${new Date().getFullYear()}`.slice(0, 2);

    // Note, we construct the output rather than doing string replacement against the
    // format guidance pattern to avoid edge cases that would output invalid values
    const [
      // The guidance parsed from the field properties regarding expiry format
      expectedExpiryDateFormat,
      // The (localized) date pattern set that was used to parse the expiry format guidance
      expiryDateFormatPatterns,
    ] = this.getExpectedExpiryDateFormat(field);

    if (expectedExpiryDateFormat && expiryDateFormatPatterns) {
      const { Month, MonthShort, Year } = expiryDateFormatPatterns;

      const expiryDateDelimitersPattern = "\\" + CardExpiryDateDelimiters.join("\\");

      // assign the delimiter from the expected format string
      delimiter =
        expectedExpiryDateFormat.match(new RegExp(`[${expiryDateDelimitersPattern}]`, "g"))?.[0] ||
        "";

      // check if the expected format starts with a month form
      // order matters here; check long form first, since short form will match against long
      if (expectedExpiryDateFormat.indexOf(Month + delimiter) === 0) {
        useMonthPadding = true;
        orderByYear = false;
      } else if (expectedExpiryDateFormat.indexOf(MonthShort + delimiter) === 0) {
        useMonthPadding = false;
        orderByYear = false;
      } else {
        orderByYear = true;

        // short form can match against long form, but long won't match against short
        const containsLongMonthPattern = new RegExp(`${Month}`, "i");
        useMonthPadding = containsLongMonthPattern.test(expectedExpiryDateFormat);
      }

      const containsLongYearPattern = new RegExp(`${Year}`, "i");

      useYearFull = containsLongYearPattern.test(expectedExpiryDateFormat);
    }

    if (cardCipher.expMonth == null || cardCipher.expYear == null) {
      return null;
    }
    const month = useMonthPadding
      ? // Ensure zero-padding
        ("0" + cardCipher.expMonth).slice(-2)
      : // Handle zero-padded stored month values, even though they are not _expected_ to be as such
        cardCipher.expMonth.replaceAll("0", "");
    // Note: assumes the user entered an `expYear` value with a length of either 2 or 4
    const year = (currentCentury + cardCipher.expYear).slice(useYearFull ? -4 : -2);

    const combinedExpiryFillValue = (orderByYear ? [year, month] : [month, year]).join(delimiter);

    return combinedExpiryFillValue;
  }

  /**
   * Returns a string value representation of discovered guidance for a combined month and year expiration value from the field attributes
   *
   * @param {AutofillField} field
   */
  protected getExpectedExpiryDateFormat(
    field: AutofillField,
  ): [string | null, CardExpiryDateFormat | null] {
    let expectedDateFormat = null;
    let dateFormatPatterns = null;

    const expiryDateDelimitersPattern = "\\" + CardExpiryDateDelimiters.join("\\");

    CreditCardAutoFillConstants.CardExpiryDateFormats.find((dateFormat) => {
      dateFormatPatterns = dateFormat;

      const { Month, MonthShort, YearShort, Year } = dateFormat;

      // Non-exhaustive coverage of field guidances. Some uncovered edge cases: ". " delimiter, space-delimited delimiters ("mm / yyyy").
      // We should consider if added whitespace is for improved readability of user-guidance or actually desired in the filled value.
      // e.g. "/((mm|m)[\/\-\.\ ]{0,1}(yyyy|yy))|((yyyy|yy)[\/\-\.\ ]{0,1}(mm|m))/gi"
      const dateFormatPattern = new RegExp(
        `((${Month}|${MonthShort})[${expiryDateDelimitersPattern}]{0,1}(${Year}|${YearShort}))|((${Year}|${YearShort})[${expiryDateDelimitersPattern}]{0,1}(${Month}|${MonthShort}))`,
        "gi",
      );

      return CreditCardAutoFillConstants.CardAttributesExtended.find((attributeName) => {
        const fieldAttributeValue = field[attributeName]?.toLocaleLowerCase();

        const fieldAttributeMatch = fieldAttributeValue?.match(dateFormatPattern);
        // break find as soon as a match is found

        if (fieldAttributeMatch?.length) {
          expectedDateFormat = fieldAttributeMatch[0];

          // remove any irrelevant characters
          const irrelevantExpiryCharactersPattern = new RegExp(
            // "or digits" to ensure numbers are removed from guidance pattern, which aren't covered by ^\w
            `[^\\w${expiryDateDelimitersPattern}]|[\\d]`,
            "gi",
          );
          expectedDateFormat.replaceAll(irrelevantExpiryCharactersPattern, "");

          return true;
        }

        return false;
      });
    });
    // @TODO if expectedDateFormat is still null, and there is a `pattern` attribute, cycle
    // through generated formatted values, checking against the provided regex pattern

    return [expectedDateFormat, dateFormatPatterns];
  }

  /**
   * Generates the autofill script for the specified page details and identity cipher item.
   *
   * @param fillScript - Object to store autofill script, passed between method references
   * @param pageDetails - The details of the page to autofill
   * @param filledFields - The fields that have already been filled, passed between method references
   * @param options - Contains data used to fill cipher items
   */
  protected generateIdentityFillScript(
    fillScript: AutofillScript,
    pageDetails: AutofillPageDetails,
    filledFields: { [id: string]: AutofillField },
    options: GenerateFillScriptOptions,
  ): AutofillScript | null {
    const identity = options.cipher.identity;
    if (!identity) {
      return null;
    }

    for (let fieldsIndex = 0; fieldsIndex < pageDetails.fields.length; fieldsIndex++) {
      const field = pageDetails.fields[fieldsIndex];
      if (this.excludeFieldFromIdentityFill(field)) {
        continue;
      }

      const keywordsList = this.getIdentityAutofillFieldKeywords(field);
      const keywordsCombined = keywordsList.join(",");
      if (this.shouldMakeIdentityTitleFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.title, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityNameFillScript(filledFields, keywordsList)) {
        if (options.remoteItemPlanning) this.makeScriptActionWithValue(fillScript, "identity:fullName", field, filledFields);
        else this.makeIdentityNameFillScript(fillScript, filledFields, field, identity);
        continue;
      }

      if (this.shouldMakeIdentityFirstNameFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.firstName, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityMiddleNameFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.middleName, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityLastNameFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.lastName, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityEmailFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.email, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityAddress1FillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.address1, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityAddress2FillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.address2, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityAddress3FillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.address3, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityAddressFillScript(filledFields, keywordsList)) {
        if (options.remoteItemPlanning) this.makeScriptActionWithValue(fillScript, "identity:fullAddress", field, filledFields);
        else this.makeIdentityAddressFillScript(fillScript, filledFields, field, identity);
        continue;
      }

      if (this.shouldMakeIdentityPostalCodeFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.postalCode, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityCityFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.city, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityStateFillScript(filledFields, keywordsCombined)) {
        if (options.remoteItemPlanning) this.makeScriptActionWithValue(fillScript, "identity:state", field, filledFields);
        else this.makeIdentityStateFillScript(fillScript, filledFields, field, identity);
        continue;
      }

      if (this.shouldMakeIdentityCountryFillScript(filledFields, keywordsCombined)) {
        if (options.remoteItemPlanning) this.makeScriptActionWithValue(fillScript, "identity:country", field, filledFields);
        else this.makeIdentityCountryFillScript(fillScript, filledFields, field, identity);
        continue;
      }

      if (this.shouldMakeIdentityPhoneFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.phone, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityUserNameFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.username, field, filledFields);
        continue;
      }

      if (this.shouldMakeIdentityCompanyFillScript(filledFields, keywordsCombined)) {
        this.makeScriptActionWithValue(fillScript, identity.company, field, filledFields);
      }
    }

    return fillScript;
  }

  /**
   * Generates the autofill script for an SSH key cipher. Fills the SSH public key into the
   * key field (a textarea on "add SSH key" forms such as GitHub and GitLab) and the cipher
   * name into the title field. The title is only filled when a public key field is present on
   * the page, to avoid matching generic "title"/"name" inputs on unrelated forms.
   *
   * @param fillScript - The autofill script to add to
   * @param pageDetails - The collected page details
   * @param filledFields - The fields that have already been filled
   * @param options - The fill script generation options
   */
  protected generateSshKeyFillScript(
    fillScript: AutofillScript,
    pageDetails: AutofillPageDetails,
    filledFields: { [id: string]: AutofillField },
    options: GenerateFillScriptOptions,
  ): AutofillScript | null {
    const sshKey = options.cipher.sshKey;
    if (!sshKey) {
      return null;
    }

    const hasPublicKeyField = pageDetails.fields.some((field) => this.isSshPublicKeyField(field));

    let publicKeyFilled = false;
    let titleFilled = false;
    for (let fieldsIndex = 0; fieldsIndex < pageDetails.fields.length; fieldsIndex++) {
      const field = pageDetails.fields[fieldsIndex];
      if (this.excludeFieldFromSshKeyFill(field)) {
        continue;
      }

      if (!publicKeyFilled && this.isSshPublicKeyField(field)) {
        publicKeyFilled = true;
        this.makeScriptActionWithValue(fillScript, sshKey.publicKey, field, filledFields);
        continue;
      }

      if (hasPublicKeyField && !titleFilled && this.isSshTitleField(field)) {
        titleFilled = true;
        this.makeScriptActionWithValue(fillScript, options.cipher.name, field, filledFields);
        continue;
      }
    }

    return fillScript;
  }

  /**
   * Identifies if the current field should be excluded from triggering autofill of the SSH
   * key cipher. Unlike the identity check, textareas are NOT excluded since the SSH public
   * key field is itself a textarea.
   *
   * @param field - The field to check
   */
  protected excludeFieldFromSshKeyFill(field: AutofillField): boolean {
    return (
      AutofillScriptGenerator.isExcludedFieldType(field, [
        "password",
        ...AutoFillConstants.ExcludedAutofillTypes,
      ]) || !field.viewable
    );
  }

  /**
   * Gathers all unique keyword identifiers from a field that can be used to determine which
   * SSH key value should be filled.
   *
   * @param field - The field to gather keywords from
   */
  protected getSshKeyAutofillFieldKeywords(field: AutofillField): string[] {
    const keywords: Set<string> = new Set();
    for (let index = 0; index < SshKeyAutoFillConstants.SshKeyAttributes.length; index++) {
      const attribute = SshKeyAutoFillConstants.SshKeyAttributes[index];
      const value = field[attribute];
      if (value != null && typeof value === "string") {
        keywords.add(
          value
            .trim()
            .toLowerCase()
            .replace(/[^a-z0-9]+/gi, ""),
        );
      }
    }

    return Array.from(keywords);
  }

  /**
   * Identifies if a field is the SSH public key field. Requires a textarea (the shape used by
   * GitHub/GitLab) combined with a strong SSH signal: an algorithm prefix in the placeholder
   * or value (e.g. "ssh-rsa"), GitLab's `data-supported-algorithms` attribute, or a "key"
   * keyword. Requiring the textarea avoids matching single-line inputs such as `api_key`.
   *
   * @param field - The field to check
   */
  protected isSshPublicKeyField(field: AutofillField): boolean {
    if (field.tagName !== "textarea") {
      return false;
    }

    if (this.sshFieldHasAlgorithmSignal(field)) {
      return true;
    }

    const keywords = this.getSshKeyAutofillFieldKeywords(field);
    return keywords.some((keyword) =>
      AutofillScriptGenerator.isFieldMatch(keyword, SshKeyAutoFillConstants.PublicKeyFieldNames),
    );
  }

  /**
   * Identifies if a field exposes an SSH algorithm signal, either an algorithm prefix in the
   * placeholder/value/labels or the `data-supported-algorithms` attribute.
   *
   * @param field - The field to check
   */
  protected sshFieldHasAlgorithmSignal(field: AutofillField): boolean {
    const haystack = [
      field.placeholder,
      field.value,
      field.dataSetValues,
      field["label-tag"],
      field["label-top"],
      field["label-left"],
    ]
      .filter((value): value is string => typeof value === "string")
      .join(" ")
      .toLowerCase();

    if (haystack.includes(SshKeyAutoFillConstants.SupportedAlgorithmsAttribute)) {
      return true;
    }

    return SshKeyAutoFillConstants.PublicKeyAlgorithmPrefixes.some((prefix) =>
      haystack.includes(prefix),
    );
  }

  /**
   * Identifies if a field is the SSH key title field. Limited to non-textarea inputs whose
   * keywords match a title field name. Callers should additionally confirm a public key field
   * is present before filling.
   *
   * @param field - The field to check
   */
  protected isSshTitleField(field: AutofillField): boolean {
    if (field.tagName === "textarea" || this.isSshPublicKeyField(field)) {
      return false;
    }

    const keywords = this.getSshKeyAutofillFieldKeywords(field);
    return keywords.some((keyword) =>
      AutofillScriptGenerator.isFieldMatch(keyword, SshKeyAutoFillConstants.TitleFieldNames),
    );
  }

  /**
   * Identifies if the current field should be excluded from triggering autofill of the identity cipher.
   *
   * @param field - The field to check
   */
  protected excludeFieldFromIdentityFill(field: AutofillField): boolean {
    return (
      AutofillScriptGenerator.isExcludedFieldType(field, [
        "password",
        ...AutoFillConstants.ExcludedAutofillTypes,
      ]) ||
      (field.autoCompleteType != null &&
        [...AutoFillConstants.ExcludedIdentityAutocompleteTypes].some((excludedToken) =>
          AutofillScriptGenerator.autoCompleteTypeIncludesToken(field.autoCompleteType, excludedToken),
        )) ||
      !field.viewable
    );
  }

  /**
   * Gathers all unique keyword identifiers from a field that can be used to determine what
   * identity value should be filled.
   *
   * @param field - The field to gather keywords from
   */
  protected getIdentityAutofillFieldKeywords(field: AutofillField): string[] {
    const keywords: Set<string> = new Set();
    for (let index = 0; index < IdentityAutoFillConstants.IdentityAttributes.length; index++) {
      const attribute = IdentityAutoFillConstants.IdentityAttributes[index];
      const value = field[attribute];
      if (value != null && typeof value === "string") {
        keywords.add(
          value
            .trim()
            .toLowerCase()
            .replace(/[^a-zA-Z0-9]+/g, ""),
        );
      }
    }

    return Array.from(keywords);
  }

  /**
   * Identifies if a fill script action for the identity title
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityTitleFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.title &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.TitleFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity name
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityNameFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string[],
  ): boolean {
    return (
      !filledFields.name &&
      keywords.some((keyword) =>
        AutofillScriptGenerator.isFieldMatch(
          keyword,
          IdentityAutoFillConstants.FullNameFieldNames,
          IdentityAutoFillConstants.FullNameFieldNameValues,
        ),
      )
    );
  }

  /**
   * Identifies if a fill script action for the identity first name
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityFirstNameFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.firstName &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.FirstnameFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity middle name
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityMiddleNameFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.middleName &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.MiddlenameFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity last name
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityLastNameFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.lastName &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.LastnameFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity email
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityEmailFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.email &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.EmailFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity address
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityAddressFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string[],
  ): boolean {
    return (
      !filledFields.address &&
      keywords.some((keyword) =>
        AutofillScriptGenerator.isFieldMatch(
          keyword,
          IdentityAutoFillConstants.AddressFieldNames,
          IdentityAutoFillConstants.AddressFieldNameValues,
        ),
      )
    );
  }

  /**
   * Identifies if a fill script action for the identity address1
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityAddress1FillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.address1 &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.Address1FieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity address2
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityAddress2FillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.address2 &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.Address2FieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity address3
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityAddress3FillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.address3 &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.Address3FieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity postal code
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityPostalCodeFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.postalCode &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.PostalCodeFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity city
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityCityFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.city &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.CityFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity state
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityStateFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.state &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.StateFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity country
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityCountryFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.country &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.CountryFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity phone
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityPhoneFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.phone &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.PhoneFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity username
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityUserNameFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.username &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.UserNameFieldNames)
    );
  }

  /**
   * Identifies if a fill script action for the identity company
   * field should be created for the provided field.
   *
   * @param filledFields - The fields that have already been filled
   * @param keywords - The keywords from the field
   */
  protected shouldMakeIdentityCompanyFillScript(
    filledFields: Record<string, AutofillField>,
    keywords: string,
  ): boolean {
    return (
      !filledFields.company &&
      AutofillScriptGenerator.isFieldMatch(keywords, IdentityAutoFillConstants.CompanyFieldNames)
    );
  }

  /**
   * Creates an identity name fill script action for the provided field. This is used
   * when filling a `full name` field, using the first, middle, and last name from the
   * identity cipher item.
   *
   * @param fillScript - The autofill script to add the action to
   * @param filledFields - The fields that have already been filled
   * @param field - The field to fill
   * @param identity - The identity cipher item
   */
  protected makeIdentityNameFillScript(
    fillScript: AutofillScript,
    filledFields: Record<string, AutofillField>,
    field: AutofillField,
    identity: IdentityView,
  ) {
    let name = "";
    if (identity.firstName) {
      name += identity.firstName;
    }

    if (identity.middleName) {
      name += !name ? identity.middleName : ` ${identity.middleName}`;
    }

    if (identity.lastName) {
      name += !name ? identity.lastName : ` ${identity.lastName}`;
    }

    this.makeScriptActionWithValue(fillScript, name, field, filledFields);
  }

  /**
   * Creates an identity address fill script action for the provided field. This is used
   * when filling a generic `address` field, using the address1, address2, and address3
   * from the identity cipher item.
   *
   * @param fillScript - The autofill script to add the action to
   * @param filledFields - The fields that have already been filled
   * @param field - The field to fill
   * @param identity - The identity cipher item
   */
  protected makeIdentityAddressFillScript(
    fillScript: AutofillScript,
    filledFields: Record<string, AutofillField>,
    field: AutofillField,
    identity: IdentityView,
  ) {
    if (!identity.address1) {
      return;
    }

    let address = identity.address1;

    if (identity.address2) {
      address += `, ${identity.address2}`;
    }

    if (identity.address3) {
      address += `, ${identity.address3}`;
    }

    this.makeScriptActionWithValue(fillScript, address, field, filledFields);
  }

  /**
   * Creates an identity state fill script action for the provided field. This is used
   * when filling a `state` field, using the state value from the identity cipher item.
   * If the state value is a full name, it will be converted to an ISO code.
   *
   * @param fillScript - The autofill script to add the action to
   * @param filledFields - The fields that have already been filled
   * @param field - The field to fill
   * @param identity - The identity cipher item
   */
  protected makeIdentityStateFillScript(
    fillScript: AutofillScript,
    filledFields: Record<string, AutofillField>,
    field: AutofillField,
    identity: IdentityView,
  ) {
    if (!identity.state) {
      return;
    }

    if (identity.state.length <= 2) {
      this.makeScriptActionWithValue(fillScript, identity.state, field, filledFields);
      return;
    }

    const stateLower = identity.state.toLowerCase();
    const isoState =
      IdentityAutoFillConstants.IsoStates[stateLower] ||
      IdentityAutoFillConstants.IsoProvinces[stateLower];
    if (isoState) {
      this.makeScriptActionWithValue(fillScript, isoState, field, filledFields);
    }
  }

  /**
   * Creates an identity country fill script action for the provided field. This is used
   * when filling a `country` field, using the country value from the identity cipher item.
   * If the country value is a full name, it will be converted to an ISO code.
   *
   * @param fillScript - The autofill script to add the action to
   * @param filledFields - The fields that have already been filled
   * @param field - The field to fill
   * @param identity - The identity cipher item
   */
  protected makeIdentityCountryFillScript(
    fillScript: AutofillScript,
    filledFields: Record<string, AutofillField>,
    field: AutofillField,
    identity: IdentityView,
  ) {
    if (!identity.country) {
      return;
    }

    if (identity.country.length <= 2) {
      this.makeScriptActionWithValue(fillScript, identity.country, field, filledFields);
      return;
    }

    const countryLower = identity.country.toLowerCase();
    const isoCountry = IdentityAutoFillConstants.IsoCountries[countryLower];
    if (isoCountry) {
      this.makeScriptActionWithValue(fillScript, isoCountry, field, filledFields);
    }
  }

  /**
   * Accepts an HTMLInputElement type value and a list of
   * excluded types and returns true if the type is excluded.
   * @param {string} type
   * @param {string[]} excludedTypes
   * @returns {boolean}
   * @private
   */
  protected static isExcludedType(type: string, excludedTypes: string[]) {
    return excludedTypes.indexOf(type) > -1;
  }

  /**
   * Identifies if a passed field contains text artifacts that identify it as a search field.
   *
   * @param field - The autofill field that we are validating as a search field
   */
  protected static isSearchField(field: AutofillField) {
    const matchFieldAttributeValues = [field.type, field.htmlName, field.htmlID, field.placeholder];
    for (let attrIndex = 0; attrIndex < matchFieldAttributeValues.length; attrIndex++) {
      const attributeValue = matchFieldAttributeValues[attrIndex];
      if (!attributeValue) {
        continue;
      }

      // Separate camel case words and case them to lower case values
      const camelCaseSeparatedFieldAttribute = attributeValue
        .replace(/([a-z])([A-Z])/g, "$1 $2")
        .toLowerCase();
      // Split the attribute by non-alphabetical characters to get the keywords
      const attributeKeywords = camelCaseSeparatedFieldAttribute.split(/[^a-z]/gi);

      for (let keywordIndex = 0; keywordIndex < attributeKeywords.length; keywordIndex++) {
        if (AutofillScriptGenerator.searchFieldNamesSet.has(attributeKeywords[keywordIndex])) {
          return true;
        }
      }
    }

    return false;
  }

  static isExcludedFieldType(field: AutofillField, excludedTypes: string[]) {
    if (AutofillScriptGenerator.forCustomFieldsOnly(field)) {
      return true;
    }

    if (field.type != null && this.isExcludedType(field.type, excludedTypes)) {
      return true;
    }

    // Check if the input is an untyped/mistyped search input
    return this.isSearchField(field);
  }

  /**
   * Accepts the value of a field, a list of possible options that define if
   * a field can be matched to a vault cipher, and a secondary optional list
   * of options that define if a field can be matched to a vault cipher. Returns
   * true if the field value matches one of the options.
   * @param {string} value
   * @param {string[]} options
   * @param {string[]} containsOptions
   * @returns {boolean}
   * @private
   */
  protected static isFieldMatch(
    value: string,
    options: string[],
    containsOptions?: string[],
  ): boolean {
    value = value
      .trim()
      .toLowerCase()
      .replace(/[^a-zA-Z0-9]+/g, "");
    for (let i = 0; i < options.length; i++) {
      let option = options[i];
      const checkValueContains = containsOptions == null || containsOptions.indexOf(option) > -1;
      option = option.toLowerCase().replace(/-/g, "");
      if (value === option || (checkValueContains && value.indexOf(option) > -1)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Helper method used to create a script action for a field. Conditionally
   * accepts a fieldProp value that will be used in place of the dataProp value.
   * @param {AutofillScript} fillScript
   * @param cipherData
   * @param {{[p: string]: AutofillField}} fillFields
   * @param {{[p: string]: AutofillField}} filledFields
   * @param {string} dataProp
   * @param {string} fieldProp
   * @private
   */
  protected makeScriptAction(
    fillScript: AutofillScript,
    cipherData: any,
    fillFields: { [id: string]: AutofillField },
    filledFields: { [id: string]: AutofillField },
    dataProp: string,
    fieldProp?: string,
  ) {
    fieldProp = fieldProp || dataProp;
    const field = fillFields[fieldProp];
    if (field != null) {
      this.makeScriptActionWithValue(fillScript, cipherData[dataProp], field, filledFields);
    }
  }

  /**
   * Handles updating the list of filled fields and adding a script action
   * to the fill script. If a select field is passed as part of the fill options,
   * we iterate over the options to check if the passed value matches one of the
   * options. If it does, we add a script action to select the option.
   * @param {AutofillScript} fillScript
   * @param dataValue
   * @param {AutofillField} field
   * @param {{[p: string]: AutofillField}} filledFields
   * @private
   */
  protected makeScriptActionWithValue(
    fillScript: AutofillScript,
    dataValue: any,
    field: AutofillField,
    filledFields: { [id: string]: AutofillField },
  ) {
    let doFill = false;
    if (AutofillScriptGenerator.hasValue(dataValue) && field) {
      if (field.type === "select-one" && field.selectInfo && field.selectInfo.options) {
        for (let i = 0; i < field.selectInfo.options.length; i++) {
          const option = field.selectInfo.options[i];
          for (let j = 0; j < option.length; j++) {
            if (
              AutofillScriptGenerator.hasValue(option[j]) &&
              option[j].toLowerCase() === dataValue.toLowerCase()
            ) {
              doFill = true;
              if (option.length > 1) {
                dataValue = option[1];
              }
              break;
            }
          }

          if (doFill) {
            break;
          }
        }
      } else {
        doFill = true;
      }
    }

    if (doFill) {
      filledFields[field.opid] = field;
      AutofillScriptGenerator.fillByOpid(fillScript, field, dataValue);
    }
  }

  static valueIsLikePassword(value: string) {
    if (value == null) {
      return false;
    }
    // Removes all whitespace, _ and - characters
    const cleanedValue = value.toLowerCase().replace(/[\s_-]/g, "");

    if (cleanedValue.indexOf("password") < 0) {
      return false;
    }

    return !AutoFillConstants.PasswordFieldExcludeList.some((i) => cleanedValue.indexOf(i) > -1);
  }

  static fieldHasDisqualifyingAttributeValue(field: AutofillField) {
    const checkedAttributeValues = [field.htmlID, field.htmlName, field.placeholder];
    let valueIsOnExclusionList = false;

    for (let i = 0; i < checkedAttributeValues.length; i++) {
      const checkedAttributeValue = checkedAttributeValues[i];
      const cleanedValue = checkedAttributeValue?.toLowerCase().replace(/[\s_-]/g, "");

      valueIsOnExclusionList = Boolean(
        cleanedValue && AutoFillConstants.FieldIgnoreList.some((i) => cleanedValue.indexOf(i) > -1),
      );

      if (valueIsOnExclusionList) {
        break;
      }
    }

    return valueIsOnExclusionList;
  }

  protected static collectExcludedPasswordFieldIds(pageDetails: AutofillPageDetails): Set<string> {
    const passwordFieldsByForm = new Map<string | null, AutofillField[]>();
    for (const field of pageDetails.fields) {
      if (field.type !== "password" || field.disabled) {
        continue;
      }
      const formKey = field.form ?? null;
      const fieldsForForm = passwordFieldsByForm.get(formKey);
      if (fieldsForForm) {
        fieldsForForm.push(field);
      } else {
        passwordFieldsByForm.set(formKey, [field]);
      }
    }

    const isCurrentPassword = (f: AutofillField) =>
      AutofillScriptGenerator.autoCompleteTypeIncludesToken(
        f.autoCompleteType,
        AutoFillConstants.AutocompleteCurrentPassword,
      );

    const excluded = new Set<string>();
    for (const [, passwordFields] of passwordFieldsByForm) {
      if (passwordFields.length >= 2 && passwordFields.some(isCurrentPassword)) {
        for (const field of passwordFields) {
          if (!isCurrentPassword(field)) {
            excluded.add(field.opid);
          }
        }
      }
    }
    return excluded;
  }

  /**
   * Accepts a pageDetails object with a list of fields and returns a list of
   * fields that are likely to be password fields.
   * @param {AutofillPageDetails} pageDetails
   * @param {boolean} canBeHidden
   * @param {boolean} canBeReadOnly
   * @param {boolean} mustBeEmpty
   * @param {boolean} fillNewPassword
   * @param {InlineMenuFillType} inlineMenuFillType
   * @returns {AutofillField[]}
   */
  static loadPasswordFields(
    pageDetails: AutofillPageDetails,
    canBeHidden: boolean,
    canBeReadOnly: boolean,
    mustBeEmpty: boolean,
    fillNewPassword: boolean,
    inlineMenuFillType?: InlineMenuFillType,
  ) {
    const arr: AutofillField[] = [];

    const excludedPasswordFieldOpids =
      fillNewPassword && inlineMenuFillType === InlineMenuFillTypes.PasswordGeneration
        ? new Set<string>()
        : AutofillScriptGenerator.collectExcludedPasswordFieldIds(pageDetails);

    pageDetails.fields.forEach((f) => {
      const isPassword = f.type === "password";
      if (
        !isPassword &&
        AutofillScriptGenerator.isExcludedFieldType(f, AutoFillConstants.ExcludedAutofillLoginTypes)
      ) {
        return;
      }

      // If any attribute values match disqualifying values, the entire field should not be used
      if (AutofillScriptGenerator.fieldHasDisqualifyingAttributeValue(f)) {
        return;
      }

      // We want to avoid treating TOTP fields as password fields
      if (fieldContainsKeyword(f, AutoFillConstants.TotpFieldNames)) {
        return;
      }

      const isLikePassword = () => {
        if (f.type !== "text") {
          return false;
        }

        const testedValues = [f.htmlID, f.htmlName, f.placeholder];
        for (let i = 0; i < testedValues.length; i++) {
          const value = testedValues[i];
          if (value != null && AutofillScriptGenerator.valueIsLikePassword(value)) {
            return true;
          }
        }

        return false;
      };

      if (
        !f.disabled &&
        (canBeReadOnly || !f.readonly) &&
        (isPassword || isLikePassword()) &&
        (canBeHidden || f.viewable) &&
        (!mustBeEmpty || f.value == null || f.value.trim() === "") &&
        (fillNewPassword ||
          !AutofillScriptGenerator.autoCompleteTypeIncludesToken(
            f.autoCompleteType,
            AutoFillConstants.AutocompleteNewPassword,
          )) &&
        !excludedPasswordFieldOpids.has(f.opid)
      ) {
        arr.push(f);
      }
    });

    return arr;
  }

  /**
   * Determines if a password field is part of a registration/signup form.
   * @param {AutofillPageDetails} pageDetails
   * @param {AutofillField} passwordField
   * @returns {boolean}
   * @private
   */
  protected isRegistrationPasswordField(
    pageDetails: AutofillPageDetails,
    passwordField: AutofillField,
  ): boolean {
    if (!passwordField.form || !pageDetails.forms) {
      return false;
    }

    const form = pageDetails.forms[passwordField.form];
    if (!form) {
      return false;
    }

    const formIdentifierValues = [
      form.htmlID?.toLowerCase?.(),
      form.htmlName?.toLowerCase?.(),
      passwordField?.htmlID?.toLowerCase?.(),
      passwordField?.htmlName?.toLowerCase?.(),
    ].filter((value): value is string => typeof value === "string");

    return formIdentifierValues.some((value) =>
      AutoFillConstants.RegistrationKeywords.some((keyword) => value.includes(keyword)),
    );
  }

  /**
   * Accepts a pageDetails object with a list of fields and returns a list of
   * fields that are likely to be username fields.
   * @param {AutofillPageDetails} pageDetails
   * @param {AutofillField} passwordField
   * @param {boolean} canBeHidden
   * @param {boolean} canBeReadOnly
   * @param {boolean} withoutForm
   * @returns {AutofillField}
   * @private
   */
  protected findUsernameField(
    pageDetails: AutofillPageDetails,
    passwordField: AutofillField,
    canBeHidden: boolean,
    canBeReadOnly: boolean,
    withoutForm: boolean,
  ): AutofillField | null {
    let sameFormCandidate: AutofillField | null = null;
    let bestCandidate: AutofillField | null = null;

    const fieldsPrecedingPassword = pageDetails.fields.filter(
      (f) => f.elementNumber < passwordField.elementNumber,
    );

    for (const field of fieldsPrecedingPassword) {
      if (AutofillScriptGenerator.forCustomFieldsOnly(field)) {
        continue;
      }

      if (isNonLoginUsernameField(field, pageDetails)) {
        continue;
      }

      const isUsernameFieldType =
        field.type === "text" || field.type === "email" || field.type === "tel";
      if (!isUsernameFieldType) {
        continue;
      }

      // Only consider fields with non-null form values as being in the same form;
      // null forms are treated as separate
      const isInSameForm =
        field.form != null && passwordField.form != null && field.form === passwordField.form;

      const includesUsernameKeyword = fieldContainsKeyword(
        field,
        AutoFillConstants.UsernameFieldNames,
      );

      // Email/tel fields in the same form are strong candidates even when visibility
      // checks are unreliable
      const isQualifiedByType = isInSameForm && (field.type === "email" || field.type === "tel");

      const isAccessible = !field.disabled && (canBeReadOnly || !field.readonly);
      const isVisible = canBeHidden || field.viewable || isQualifiedByType;
      const isReachable = withoutForm || isInSameForm || includesUsernameKeyword;

      if (!isAccessible || !isVisible || !isReachable) {
        continue;
      }

      if (isInSameForm) {
        sameFormCandidate = field;
        // A same-form field explicitly named for username is the best possible match
        if (includesUsernameKeyword) {
          return field;
        }
      } else {
        bestCandidate = field;
      }
    }

    // Prefer a same-form candidate, fall back to any matching field
    return sameFormCandidate || bestCandidate;
  }

  /**
   * Accepts a pageDetails object with a list of fields and returns a list of
   * fields that are likely to be TOTP fields.
   * @param {AutofillPageDetails} pageDetails
   * @param {AutofillField} passwordField
   * @param {boolean} canBeHidden
   * @param {boolean} canBeReadOnly
   * @param {boolean} withoutForm
   * @returns {AutofillField}
   * @private
   */
  protected findTotpField(
    pageDetails: AutofillPageDetails,
    passwordField: AutofillField,
    canBeHidden: boolean,
    canBeReadOnly: boolean,
    withoutForm: boolean,
  ): AutofillField | null {
    let totpField: AutofillField | null = null;
    for (let i = 0; i < pageDetails.fields.length; i++) {
      const f = pageDetails.fields[i];
      if (AutofillScriptGenerator.forCustomFieldsOnly(f)) {
        continue;
      }

      const fieldIsDisqualified = AutofillScriptGenerator.fieldHasDisqualifyingAttributeValue(f);

      if (
        !fieldIsDisqualified &&
        !f.disabled &&
        (canBeReadOnly || !f.readonly) &&
        (withoutForm || f.form === passwordField.form) &&
        (canBeHidden || f.viewable) &&
        (f.type === "text" ||
          f.type === "number" ||
          // sites will commonly use tel in order to get the digit pad against semantic recommendations
          f.type === "tel") &&
        fieldContainsKeyword(f, [
          ...AutoFillConstants.TotpFieldNames,
          ...AutoFillConstants.AmbiguousTotpFieldNames,
        ]) &&
        !fieldContainsKeyword(f, [...AutoFillConstants.RecoveryCodeFieldNames])
      ) {
        totpField = f;

        if (
          this.findMatchingFieldIndex(f, [
            ...AutoFillConstants.TotpFieldNames,
            ...AutoFillConstants.AmbiguousTotpFieldNames,
          ]) > -1 ||
          f.autoCompleteType === "one-time-code"
        ) {
          // We found an exact match. No need to keep looking.
          break;
        }
      }
    }

    return totpField;
  }

  /**
   * Accepts a field and returns the index of the first matching property
   * present in a list of attribute names.
   * @param {AutofillField} field
   * @param {string[]} names
   * @returns {number}
   * @private
   */
  protected findMatchingFieldIndex(field: AutofillField, names: string[]): number {
    for (let i = 0; i < names.length; i++) {
      if (names[i].indexOf("=") > -1) {
        if (this.fieldPropertyIsPrefixMatch(field, "htmlID", names[i], "id")) {
          return i;
        }
        if (this.fieldPropertyIsPrefixMatch(field, "htmlName", names[i], "name")) {
          return i;
        }
        if (this.fieldPropertyIsPrefixMatch(field, "label-left", names[i], "label")) {
          return i;
        }
        if (this.fieldPropertyIsPrefixMatch(field, "label-right", names[i], "label")) {
          return i;
        }
        if (this.fieldPropertyIsPrefixMatch(field, "label-tag", names[i], "label")) {
          return i;
        }
        if (this.fieldPropertyIsPrefixMatch(field, "label-aria", names[i], "label")) {
          return i;
        }
        if (this.fieldPropertyIsPrefixMatch(field, "placeholder", names[i], "placeholder")) {
          return i;
        }
      }

      if (this.fieldPropertyIsMatch(field, "htmlID", names[i])) {
        return i;
      }
      if (this.fieldPropertyIsMatch(field, "htmlName", names[i])) {
        return i;
      }
      if (this.fieldPropertyIsMatch(field, "label-left", names[i])) {
        return i;
      }
      if (this.fieldPropertyIsMatch(field, "label-right", names[i])) {
        return i;
      }
      if (this.fieldPropertyIsMatch(field, "label-tag", names[i])) {
        return i;
      }
      if (this.fieldPropertyIsMatch(field, "label-aria", names[i])) {
        return i;
      }
      if (this.fieldPropertyIsMatch(field, "placeholder", names[i])) {
        return i;
      }
    }

    return -1;
  }

  /**
   * Accepts a field, property, name, and prefix and returns true if the field
   * contains a value that matches the given prefixed property.
   * @param field
   * @param {string} property
   * @param {string} name
   * @param {string} prefix
   * @param {string} separator
   * @returns {boolean}
   * @private
   */
  protected fieldPropertyIsPrefixMatch(
    field: any,
    property: string,
    name: string,
    prefix: string,
    separator = "=",
  ): boolean {
    if (name.indexOf(prefix + separator) === 0) {
      const sepIndex = name.indexOf(separator);
      const val = name.substring(sepIndex + 1);
      return val != null && this.fieldPropertyIsMatch(field, property, val);
    }
    return false;
  }

  /**
   * Identifies if a given property within a field matches the value
   * of the passed "name" parameter. If the name starts with "regex=",
   * the value is tested against a case-insensitive regular expression.
   * If the name starts with "csv=", the value is treated as a
   * comma-separated list of values to match.
   * @param field
   * @param {string} property
   * @param {string} name
   * @returns {boolean}
   * @private
   */
  protected fieldPropertyIsMatch(field: any, property: string, name: string): boolean {
    let fieldVal = field[property] as string;
    if (!AutofillScriptGenerator.hasValue(fieldVal)) {
      return false;
    }

    fieldVal = fieldVal.trim().replace(/(?:\r\n|\r|\n)/g, "");
    if (name.startsWith("regex=")) {
      try {
        const regexParts = name.split("=", 2);
        if (regexParts.length === 2) {
          const regex = new RegExp(regexParts[1], "i");
          return regex.test(fieldVal);
        }
      } catch (e) {
        // Never log the invalid regex, field contents or the original exception.
        this.planningDependencies?.logService.error("Invalid custom field expression.");
      }
    } else if (name.startsWith("csv=")) {
      const csvParts = name.split("=", 2);
      if (csvParts.length === 2) {
        const csvVals = csvParts[1].split(",");
        for (let i = 0; i < csvVals.length; i++) {
          const val = csvVals[i];
          if (val != null && val.trim().toLowerCase() === fieldVal.toLowerCase()) {
            return true;
          }
        }
        return false;
      }
    }

    return fieldVal.toLowerCase() === name;
  }

  /**
   * True if `autoCompleteType` includes `token` as a space-separated autocomplete token.
   * Handles compound tokens such as `section-login current-password`.
   */
  static autoCompleteTypeIncludesToken(
    autoCompleteType: string | null | undefined,
    token: string,
  ): boolean {
    if (autoCompleteType == null || typeof autoCompleteType !== "string") {
      return false;
    }

    const normalizedToken = token.trim().toLowerCase();
    if (!normalizedToken) {
      return false;
    }

    const parts = autoCompleteType.trim().toLowerCase().split(/\s+/);
    return parts.includes(normalizedToken);
  }

  /**
   * Accepts a string and returns true if the
   * string is not falsy and not empty.
   * @param {string} str
   * @returns {boolean}
   */
  static hasValue(str: string): boolean {
    return Boolean(str && str !== "");
  }

  /**
   * Sets the `focus_by_opid` autofill script
   * action to the last field that was filled.
   * @param {{[p: string]: AutofillField}} filledFields
   * @param {AutofillScript} fillScript
   * @returns {AutofillScript}
   */
  static setFillScriptForFocus(
    filledFields: { [id: string]: AutofillField },
    fillScript: AutofillScript,
  ): AutofillScript {
    let lastField: AutofillField | null = null;
    let lastPasswordField: AutofillField | null = null;

    for (const opid in filledFields) {
      // eslint-disable-next-line
      if (filledFields.hasOwnProperty(opid) && filledFields[opid].viewable) {
        lastField = filledFields[opid];

        if (filledFields[opid].type === "password") {
          lastPasswordField = filledFields[opid];
        }
      }
    }

    // Prioritize password field over others.
    if (lastPasswordField?.opid != null) {
      fillScript.script.push(["focus_by_opid", lastPasswordField.opid]);
    } else if (lastField?.opid != null) {
      fillScript.script.push(["focus_by_opid", lastField.opid]);
    }

    return fillScript;
  }

  /**
   * Updates a fill script to place the `click_on_opid`, `focus_on_opid`, and `fill_by_opid`
   * fill script actions associated with the provided field.
   * @param {AutofillScript} fillScript
   * @param {AutofillField} field
   * @param {string} value
   */
  static fillByOpid(fillScript: AutofillScript, field: AutofillField, value: string): void {
    if (field.maxLength && value && value.length > field.maxLength) {
      value = value.substr(0, value.length);
    }
    if (field.tagName !== "span") {
      fillScript.script.push(["click_on_opid", field.opid]);
      fillScript.script.push(["focus_by_opid", field.opid]);
    }
    fillScript.script.push(["fill_by_opid", field.opid, value]);
  }

  /**
   * Identifies if the field is a custom field, a custom
   * field is defined as a field that is a `span` element.
   * @param {AutofillField} field
   * @returns {boolean}
   */
  static forCustomFieldsOnly(field: AutofillField): boolean {
    return field.tagName === "span";
  }

}
