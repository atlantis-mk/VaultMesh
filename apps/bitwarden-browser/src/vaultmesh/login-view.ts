import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { LoginUriView } from "@bitwarden/common/vault/models/view/login-uri.view";
import { CipherRepromptType } from "@bitwarden/common/vault/enums/cipher-reprompt-type";
import type { LoginSummary } from "./contracts";

/** Project metadata into Bitwarden's presentation model; never hydrate secrets. */
export function loginSummaryView(summary: LoginSummary): CipherView {
  const cipher = new CipherView();
  cipher.id = summary.id;
  cipher.name = summary.title;
  cipher.login.username = summary.username;
  cipher.login.autofillOnPageLoad = summary.autofillOnPageLoad;
  if (summary.url) {
    const uri = new LoginUriView();
    uri.uri = summary.url;
    cipher.login.uris = [uri];
  }
  cipher.reprompt = summary.masterPasswordReprompt ? CipherRepromptType.Password : CipherRepromptType.None;
  cipher.viewPassword = false;
  return cipher;
}
