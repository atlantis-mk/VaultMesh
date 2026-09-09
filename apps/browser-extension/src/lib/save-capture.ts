import { analyzeFormSemantics, formControls, isNewPasswordControl, type SupportedControl } from "@/lib/form-discovery";
import type { PageContext } from "@/lib/protocol";

export type CapturedLogin = {
  username: string;
  password: string;
  loginId?: string;
  title?: string;
  url?: string | null;
  totpSecret?: string | null;
  additionalUrls?: string[];
  customFields?: Array<{ label: string; value: string }>;
};
export type CapturedIdentity = {
  identityId?: string;
  title: string;
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  birthDate: string | null;
  emails: Array<{ label: string; value: string; preferred: boolean }>;
  phones: Array<{ label: string; value: string; preferred: boolean }>;
  addresses: Array<{
    label: string;
    addressLine1: string;
    addressLine2: string | null;
    city: string | null;
    region: string | null;
    postalCode: string | null;
    countryCode: string | null;
    country: string | null;
    preferred: boolean;
  }>;
  organization: string | null;
  department: string | null;
  jobTitle: string | null;
  website: string | null;
};
export type CapturedCard = {
  cardId?: string;
  title: string;
  cardholderName: string;
  cardNumber: string;
  expirationMonth: number;
  expirationYear: number;
  securityCode: string | null;
  pin?: string | null;
  issuer?: string | null;
  network?: string | null;
  billingAddress: string | null;
};
export type CapturedSecret = {
  title: string;
  kind: "api-key" | "access-token" | "authenticator-key" | "client-secret" | "webhook-secret" | "database-credential" | "recovery-codes" | "certificate" | "software-license" | "identity-document" | "secure-note" | "crypto-wallet" | "other";
  secret: string;
  provider: string | null;
  account: string | null;
  environment: string | null;
  scopes: string[];
  expiresAt: string | null;
  website: string | null;
};
export type CapturedSshCredential = {
  title: string;
  host: string | null;
  port: number;
  username: string;
  password: string | null;
  publicKey: string | null;
  privateKey: string | null;
  keyPassphrase: string | null;
};
export type CapturedSaveData = {
  login?: CapturedLogin;
  identity?: CapturedIdentity;
  card?: CapturedCard;
  secrets?: CapturedSecret[];
  sshCredentials?: CapturedSshCredential[];
};

type CaptureOptions = {
  context?: PageContext;
  includeLogin?: boolean;
};

const identityTokens: Record<string, string> = {
  name: "fullName", "given-name": "firstName", "additional-name": "middleName", "family-name": "lastName",
  email: "email", tel: "phone", bday: "birthDate", organization: "organization", "organization-title": "jobTitle",
  url: "website", "address-line1": "addressLine1", "address-line2": "addressLine2", "address-level2": "city",
  "address-level1": "region", "postal-code": "postalCode", country: "country", "country-name": "countryName",
};
const cardTokens: Record<string, string> = {
  "cc-name": "cardholderName", "cc-number": "cardNumber", "cc-exp": "expiration",
  "cc-exp-month": "expirationMonth", "cc-exp-year": "expirationYear", "cc-csc": "securityCode",
};

export function captureSubmittedData(root: ParentNode, pageUrl: string, options: CaptureOptions = {}): CapturedSaveData {
  const controls = captureControls(root);
  const context = options.context ?? inferContext(controls);
  return {
    ...(options.includeLogin === false ? {} : captureLogin(controls, context)),
    ...captureIdentity(controls, pageUrl, context),
    ...captureCard(controls, pageUrl),
  };
}

export function submittedDataContext(root: ParentNode): PageContext {
  return inferContext(captureControls(root));
}

export function capturedDataSignature(data: CapturedSaveData): string {
  const login = data.login ? `${data.login.username}\u0000${data.login.password}` : "";
  const identity = data.identity ? JSON.stringify(data.identity) : "";
  const card = data.card ? `${data.card.cardNumber}\u0000${data.card.expirationMonth}\u0000${data.card.expirationYear}` : "";
  const secret = JSON.stringify(data.secrets ?? []);
  const ssh = JSON.stringify(data.sshCredentials ?? []);
  return `${login}\u0001${identity}\u0001${card}\u0001${secret}\u0001${ssh}`;
}

export function hasCapturedData(data: CapturedSaveData): boolean {
  return Boolean(data.login || data.identity || data.card || data.secrets?.length || data.sshCredentials?.length);
}

function captureLogin(controls: SupportedControl[], context: PageContext): Pick<CapturedSaveData, "login"> | {} {
  if (!["login", "signup", "password-change", "password-reset"].includes(context)) return {};
  const passwords = controls.filter((control): control is HTMLInputElement => control instanceof HTMLInputElement && control.type === "password");
  const preferred = passwords.find((control) => autocompleteTokens(control).includes("new-password"))
    ?? passwords.find((control) => isNewPasswordControl(control))
    ?? passwords[0];
  if (!preferred?.value) return {};
  const newPasswords = passwords.filter((control) => autocompleteTokens(control).includes("new-password") || isNewPasswordControl(control));
  if (newPasswords.includes(preferred) && newPasswords.some((control) => control.value !== preferred.value)) return {};
  return { login: { username: accountValue(controls), password: preferred.value } };
}

function captureIdentity(controls: SupportedControl[], pageUrl: string, context: PageContext): Pick<CapturedSaveData, "identity"> | {} {
  if (!["signup", "checkout", "profile", "unknown"].includes(context)) return {};
  const values: Record<string, string> = {};
  for (const control of controls) {
    const field = identityField(control);
    const value = controlValue(control);
    if (field && value && !values[field]) values[field] = value;
  }
  const names = splitFullName(values.fullName ?? "");
  const firstName = clean(values.firstName ?? names.firstName);
  const middleName = clean(values.middleName);
  const lastName = clean(values.lastName ?? names.lastName);
  const emails = uniqueIdentityValues(controls, "email");
  const phones = uniqueIdentityValues(controls, "phone");
  const email = emails[0]?.value ?? clean(values.email);
  const phone = phones[0]?.value ?? clean(values.phone);
  const addresses = capturedAddresses(controls);
  const addressLine1 = addresses[0]?.addressLine1 ?? clean(values.addressLine1);
  const meaningfulProfile = Boolean(firstName || lastName || phone || values.organization || values.jobTitle);
  if (!addressLine1 && !meaningfulProfile) return {};
  const hostname = safeHostname(pageUrl);
  const displayName = [firstName, middleName, lastName].filter(Boolean).join(" ");
  return {
    identity: {
      title: displayName || email || phone || (addressLine1 ? `${hostname} 地址` : hostname),
      firstName, middleName, lastName,
      birthDate: /^\d{4}-\d{2}-\d{2}$/.test(values.birthDate ?? "") ? values.birthDate! : null,
      emails: emails.length ? emails : email ? [{ label: "主要", value: email, preferred: true }] : [],
      phones: phones.length ? phones : phone ? [{ label: "主要", value: phone, preferred: true }] : [],
      addresses,
      organization: clean(values.organization), department: clean(values.department), jobTitle: clean(values.jobTitle),
      website: httpUrl(values.website),
    },
  };
}

function uniqueIdentityValues(controls: SupportedControl[], field: "email" | "phone") {
  const seen = new Set<string>();
  return controls.filter((control) => identityField(control) === field).map((control) => clean(controlValue(control))).filter((value): value is string => {
    if (!value || seen.has(value)) return false;
    seen.add(value);
    return true;
  }).slice(0, 20).map((value, index) => ({ label: index === 0 ? "主要" : `${field === "email" ? "邮箱" : "电话"} ${index + 1}`, value, preferred: index === 0 }));
}

function capturedAddresses(controls: SupportedControl[]): CapturedIdentity["addresses"] {
  const addressControls = controls.filter((control) => identityField(control) === "addressLine1");
  const addresses = addressControls.map((lineControl, index) => {
    const scope = lineControl.closest("fieldset,section,article,li,tr,form,[data-address]") ?? lineControl.parentElement;
    const scopedControls = scope ? controls.filter((control) => scope.contains(control)) : controls;
    const values: Record<string, string> = {};
    for (const control of scopedControls) {
      const field = identityField(control);
      const value = controlValue(control);
      if (field && value && !values[field]) values[field] = value;
    }
    const countryValue = clean(values.country ?? values.countryName);
    const countryCode = countryValue && /^[a-z]{2}$/i.test(countryValue) ? countryValue.toUpperCase() : null;
    const country = clean(values.countryName) ?? (countryCode ? null : countryValue);
    return {
      label: addressLabel(scopedControls),
      addressLine1: controlValue(lineControl).slice(0, 512),
      addressLine2: clean(values.addressLine2), city: clean(values.city), region: clean(values.region), postalCode: clean(values.postalCode),
      countryCode, country, preferred: index === 0,
    };
  });
  const seen = new Set<string>();
  return addresses.filter((address) => {
    const key = JSON.stringify(address, ["addressLine1", "addressLine2", "city", "region", "postalCode", "countryCode", "country"]);
    if (seen.has(key)) return false;
    seen.add(key);
    return Boolean(address.addressLine1);
  }).slice(0, 20);
}

function captureCard(controls: SupportedControl[], pageUrl: string): Pick<CapturedSaveData, "card"> | {} {
  const values: Record<string, string> = {};
  for (const control of controls) {
    const field = cardField(control);
    const value = controlValue(control);
    if (field && value && !values[field]) values[field] = value;
  }
  const cardNumber = (values.cardNumber ?? "").replace(/[^0-9]/g, "");
  if (!isLikelyCardNumber(cardNumber)) return {};
  const expiration = parseExpiration(values, controls);
  const cardholderName = clean(values.cardholderName);
  if (!expiration || !cardholderName) return {};
  const securityCode = /^\d{3,4}$/.test(values.securityCode ?? "") ? values.securityCode! : null;
  return {
    card: {
      title: `${safeHostname(pageUrl)} •••• ${cardNumber.slice(-4)}`,
      cardholderName, cardNumber, expirationMonth: expiration.month, expirationYear: expiration.year, securityCode,
      pin: cardPin(controls), issuer: cardIssuer(controls), network: cardNetwork(values.cardNumber ?? "", controls),
      billingAddress: billingAddress(controls),
    },
  };
}

function captureControls(root: ParentNode): SupportedControl[] {
  return formControls(root)
    .filter((control) => !(control instanceof HTMLInputElement && ["button", "submit", "reset", "checkbox", "radio", "file", "hidden"].includes(control.type)))
    .filter((control) => !("disabled" in control) || !control.disabled)
    .filter((control) => !control.matches(':disabled,[aria-disabled="true"]') && !control.closest('[inert],[aria-hidden="true"],[hidden]'));
}

function inferContext(controls: SupportedControl[]): PageContext {
  const representative = controls[0];
  return representative ? analyzeFormSemantics(representative).context : "unknown";
}

function accountValue(controls: SupportedControl[]): string {
  const account = controls.find((control) => {
    if (control instanceof HTMLInputElement && control.type === "password") return false;
    const tokens = autocompleteTokens(control);
    return tokens.includes("username") || tokens.includes("email") || /user(name)?|e-?mail|account|login|phone|mobile|用户名|账号|邮箱|手机/i.test(metadata(control));
  });
  return account ? controlValue(account).slice(0, 2_048) : "";
}

function identityField(control: SupportedControl): string | undefined {
  const token = autocompleteTokens(control).map((entry) => identityTokens[entry]).find(Boolean);
  if (token) return token;
  const text = metadata(control);
  if (/password|passcode|otp|card|cvv|cvc|验证码|密码|卡号|安全码/i.test(text)) return undefined;
  const patterns: Array<[string, RegExp]> = [
    ["firstName", /\b(first|given)[ _-]?name\b|名字|名(?!称)/i], ["middleName", /middle[ _-]?name|中间名/i],
    ["lastName", /\b(last|family|sur)[ _-]?name\b|姓氏|姓(?!名)/i], ["fullName", /full[ _-]?name|姓名|真实姓名/i],
    ["email", /e[ _-]?mail|电子邮件|邮箱/i], ["phone", /\b(phone|mobile|telephone|tel)\b|电话|手机/i],
    ["birthDate", /birth|birthday|出生日期|生日/i], ["organization", /organization|company|employer|单位|公司|组织/i],
    ["department", /department|division|team|部门|团队/i], ["jobTitle", /job[ _-]?title|position|职位|职务/i],
    ["website", /website|web[ _-]?site|个人网站/i], ["addressLine2", /address.*(?:line.?2|suite|unit)|楼层|房间|地址.*补充/i],
    ["addressLine1", /address|street|详细地址|街道|住址|收货地址/i], ["city", /\bcity\b|城市|市/i],
    ["region", /state|province|region|省|州|地区/i], ["postalCode", /postal|zip|邮编/i], ["country", /country|国家/i],
  ];
  const matches = patterns.filter(([, pattern]) => pattern.test(text));
  return matches.length === 1 ? matches[0]![0] : undefined;
}

function cardField(control: SupportedControl): string | undefined {
  const token = autocompleteTokens(control).map((entry) => cardTokens[entry]).find(Boolean);
  if (token) return token;
  const text = metadata(control);
  if (/card.?holder|name.?on.?card|持卡人/i.test(text)) return "cardholderName";
  if (/card.?number|cc.?num|卡号/i.test(text)) return "cardNumber";
  if (/cvv|cvc|security.?code|安全码/i.test(text)) return "securityCode";
  if (/\b(?:card[ _-]?)?pin\b|支付密码|银行卡密码/i.test(text)) return "pin";
  if (/issuer|issuing.?bank|发卡(?:行|机构)|银行名称/i.test(text)) return "issuer";
  if (/card.?network|card.?brand|卡组织|卡品牌/i.test(text)) return "network";
  if (/expir.*month|到期月/i.test(text)) return "expirationMonth";
  if (/expir.*year|到期年/i.test(text)) return "expirationYear";
  if (/expir|有效期|到期/i.test(text)) return "expiration";
  return undefined;
}

function cardPin(controls: SupportedControl[]): string | null {
  const value = controls.find((control) => cardField(control) === "pin");
  const pin = value ? controlValue(value) : "";
  return /^\d{4,12}$/.test(pin) ? pin : null;
}

function cardIssuer(controls: SupportedControl[]): string | null {
  const value = controls.find((control) => cardField(control) === "issuer");
  return value ? clean(controlValue(value))?.slice(0, 256) ?? null : null;
}

function cardNetwork(number: string, controls: SupportedControl[]): string | null {
  const explicit = controls.find((control) => cardField(control) === "network");
  if (explicit) return clean(controlValue(explicit))?.slice(0, 256) ?? null;
  const digits = number.replace(/\D/g, "");
  if (/^4/.test(digits)) return "Visa";
  if (/^(?:5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720))/.test(digits)) return "Mastercard";
  if (/^3[47]/.test(digits)) return "American Express";
  if (/^(?:6011|65|64[4-9])/.test(digits)) return "Discover";
  if (/^35/.test(digits)) return "JCB";
  if (/^62/.test(digits)) return "UnionPay";
  return null;
}

function parseExpiration(values: Record<string, string>, controls: SupportedControl[]) {
  let month = Number(values.expirationMonth);
  let year = Number(values.expirationYear);
  if ((!month || !year) && values.expiration) {
    const match = values.expiration.match(/^(\d{4})-(\d{1,2})$|^(\d{1,2})\D+(\d{2,4})$/);
    if (match) {
      month = Number(match[2] ?? match[3]);
      year = Number(match[1] ?? match[4]);
    }
  }
  if (year > 0 && year < 100) year += 2_000;
  if ((!month || !year) && controls.some((control) => cardField(control) === "expiration" && control instanceof HTMLInputElement && control.type === "month")) return null;
  return month >= 1 && month <= 12 && year >= new Date().getFullYear() && year <= new Date().getFullYear() + 30 ? { month, year } : null;
}

function billingAddress(controls: SupportedControl[]): string | null {
  const parts = controls.filter((control) => autocompleteTokens(control).includes("billing") || /billing|账单/i.test(metadata(control)))
    .filter((control) => Boolean(identityField(control))).map(controlValue);
  return parts.length ? Array.from(new Set(parts)).join(", ").slice(0, 10_000) : null;
}

function addressLabel(controls: SupportedControl[]) {
  const text = controls.map((control) => `${autocompleteTokens(control).join(" ")} ${metadata(control)}`).join(" ");
  return /billing|账单/i.test(text) ? "账单" : /shipping|delivery|收货|配送/i.test(text) ? "收货" : "主要";
}

function isLikelyCardNumber(number: string) {
  if (!/^\d{12,19}$/.test(number)) return false;
  let sum = 0;
  let double = false;
  for (let index = number.length - 1; index >= 0; index -= 1) {
    let digit = Number(number[index]);
    if (double && (digit *= 2) > 9) digit -= 9;
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

function splitFullName(value: string) {
  const normalized = clean(value) ?? "";
  if (/^[\u3400-\u9fff]{2,4}$/.test(normalized)) return { lastName: normalized.slice(0, 1), firstName: normalized.slice(1) };
  const parts = normalized.split(/\s+/).filter(Boolean);
  return parts.length > 1 ? { firstName: parts[0], lastName: parts.slice(1).join(" ") } : { firstName: normalized || undefined, lastName: undefined };
}

function autocompleteTokens(control: SupportedControl) {
  return (control.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).filter(Boolean);
}

function metadata(control: SupportedControl) {
  const labels = control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement || control instanceof HTMLSelectElement
    ? Array.from(control.labels ?? []).map((label) => label.textContent ?? "") : [];
  return [...autocompleteTokens(control), ...labels, control.getAttribute("aria-label") ?? "", control.getAttribute("name") ?? "", control.id, control.getAttribute("placeholder") ?? ""].join(" ");
}

function controlValue(control: SupportedControl): string {
  const value = control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement || control instanceof HTMLSelectElement ? control.value : control.textContent ?? "";
  return value.trim().slice(0, 10_000);
}

function clean(value: string | undefined): string | null {
  const normalized = value?.replace(/\s+/g, " ").trim() ?? "";
  return normalized ? normalized.slice(0, 2_048) : null;
}

function httpUrl(value: string | undefined): string | null {
  if (!value) return null;
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.href.slice(0, 2_048) : null; } catch { return null; }
}

function safeHostname(pageUrl: string) {
  try { return new URL(pageUrl).hostname.slice(0, 256) || "网站"; } catch { return "网站"; }
}
