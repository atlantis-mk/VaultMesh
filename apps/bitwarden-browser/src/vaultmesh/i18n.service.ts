import { Injectable } from "@angular/core";
import { BehaviorSubject, of } from "rxjs";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";

/** Packaged browser translations only: no account state, storage or network. */
@Injectable()
export class VaultMeshI18nService extends I18nService {
  readonly userSetLocale$ = of(undefined);
  readonly translationLocale = chrome.i18n.getUILanguage();
  readonly locale$ = new BehaviorSubject(this.translationLocale);
  readonly supportedTranslationLocales = [this.translationLocale];
  readonly collator = new Intl.Collator(this.translationLocale);
  readonly localeNames = new Map([[this.translationLocale, this.translationLocale]]);
  async init(): Promise<void> {}
  async setLocale(): Promise<void> { /* Locale follows the browser's packaged message selection. */ }
  t(id: string, ...params: (string | number)[]): string {
    return chrome.i18n.getMessage(id, params.map(String)) || id;
  }
  translate(id: string, ...params: string[]): string { return this.t(id, ...params); }
}
