import type { ContentMessage, FieldDescriptor, PageContext } from "@/lib/protocol";
import { createUuid } from "@/lib/uuid";
import fieldPolicy from "../../../tauri-desktop/src/shared/autofill-field-policy.json";

type NativeControl = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
export type SupportedControl = NativeControl | HTMLElement;
type DiscoveryRoot = Document | ShadowRoot;
export type AutofillFieldKind = "login" | "card" | "identity" | "secret" | "ssh";
export type PasswordFieldPurpose = "current" | "new";
export type CredentialFieldRole = "account" | "current-password" | "new-password" | "confirmation-password" | "otp" | "other";
export type SemanticConfidence = "high" | "medium" | "low";
export type ControlSemanticAnalysis = {
  context: PageContext;
  role: CredentialFieldRole;
  confidence: SemanticConfidence;
  score: number;
  competingScore: number;
  reasons: string[];
};

const MAX_FIELDS = 300;
const MAX_OPTIONS = 200;
const CONTROL_READY_TIMEOUT_MS = 3_000;
const CONTROL_READY_POLL_MS = 50;
const CHARACTER_DELAY_MS = 32;
const FIELD_DELAY_MS = 120;
const TEXT_INPUT_TYPES = new Set(["", "text", "email", "tel", "url", "search", "password", "number", "month", "date", "datetime-local", "time"]);
// Password and payment controls are discovered without values. The desktop
// disclosure policy decides whether a selected login/card may populate them.
const SENSITIVE_METADATA = /\b(ssn|social[\s-]?security|tax|passport|national[\s-]?id|government|driver[\s-]?licen[cs]e)\b|身份证|护照/i;
const CURRENT_PASSWORD_METADATA = /\b(current|old|existing|previous|login)\s*[\s_-]*pass(word|code)\b|当前密码|原密码|旧密码|登录密码/i;
const NEW_PASSWORD_METADATA = /\b(new|set|create|choose|reset|confirm|repeat|verify|re[\s_-]*enter)\s*[\s_-]*pass(word|code)\b|password[\s_-]*(confirmation|confirm)|新密码|设置密码|创建密码|重置密码|确认密码|再次(?:输入)?密码|重复密码/i;
const CONFIRM_PASSWORD_METADATA = /\b(confirm|repeat|verify|re[\s_-]*enter)\s*[\s_-]*pass(word|code)\b|password[\s_-]*(confirmation|confirm)|确认密码|再次(?:输入)?密码|重复密码/i;
const OTP_METADATA = /\b(?:otp|totp|2fa|mfa)\b|one[\s_-]?time[\s_-]?(?:code|password|passcode|token)|(?:verification|authentication|authenticator)[\s_-]?(?:code|passcode|token|pin)|two[\s_-]?factor|验证码|动态码|认证码/i;
const LOGIN_SEMANTICS = /\b(?:log[\s_-]*in|sign[\s_-]*in|account[\s_-]*login)\b|登录|登入/i;
const SIGNUP_SEMANTICS = /\b(?:sign[\s_-]*up|register|registration|create\s+(?:an?\s+)?account|join\s+now)\b|注册|创建账号|创建账户/i;
const RESET_SEMANTICS = /\b(?:forgot|recover|reset|set\s+(?:a\s+)?new)\s*(?:pass(?:word|code))?\b|忘记密码|找回密码|重置密码|设置新密码/i;
const CHANGE_PASSWORD_SEMANTICS = /\b(?:change|update)\s+pass(?:word|code)\b|修改密码|更改密码|更新密码/i;
const LOGIN_ROUTE = /(?:^|\/)(?:login|log-in|signin|sign-in|auth)(?:\/|$)/i;
const SIGNUP_ROUTE = /(?:^|\/)(?:signup|sign-up|register|registration|create-account)(?:\/|$)/i;
const RESET_ROUTE = /(?:^|\/)(?:forgot-password|recover-password|reset-password|password-reset)(?:\/|$)/i;
const CHANGE_PASSWORD_ROUTE = /(?:^|\/)(?:change-password|password-change|update-password)(?:\/|$)/i;

export function discoverFields(root: DiscoveryRoot) {
  const handles = new Map<string, SupportedControl>();
  const descriptors: FieldDescriptor[] = [];
  const controls = composedControls(root)
    .filter(isSupportedControl)
    .map((control, index) => ({ control, index, priority: discoveryPriority(control) }))
    .sort((left, right) => right.priority - left.priority || left.index - right.index)
    .slice(0, MAX_FIELDS);

  for (const { control } of controls) {

    const descriptor = buildDescriptor(control);
    if (!descriptor) {
      continue;
    }

    handles.set(descriptor.handle, control);
    descriptors.push(descriptor);
  }

  return { handles, descriptors };
}

/**
 * History-state navigation keeps a content script alive, but changes the
 * page context in which its discovery handles were issued. Clear those
 * handles before a replacement scan so an approval for the old route cannot
 * write into a reused same-document control.
 */
export function discardFieldHandles(handles: Map<string, SupportedControl>) {
  handles.clear();
}

function discoveryPriority(control: SupportedControl) {
  if (classifyControl(control)) return 3;
  if (control.closest('form,[role="form"],dialog,[role="dialog"]')) return 2;
  return 1;
}

export function documentHttpOrigin(document: Document) {
  const ownOrigin = document.defaultView?.location.origin ?? "";
  if (isHttpOrigin(ownOrigin)) return ownOrigin;
  try {
    const topOrigin = document.defaultView?.top?.location.origin ?? "";
    return isHttpOrigin(topOrigin) ? topOrigin : ownOrigin;
  } catch {
    return ownOrigin;
  }
}

export function classifyControl(control: Element): AutofillFieldKind | null {
  if (!isControlElement(control) || !isSupportedControl(control)) return null;
  const metadata = getMetadata(control);
  const tokens = metadata.autocomplete;
  const text = qualificationText(metadata);
  if (isNonAutofillControl(control, text)) return null;
  const semantics = analyzeControlSemantics(control);
  const context = semantics.context;
  if (context === "developer-secret" && !(control instanceof HTMLSelectElement) && /\b(?:api key|access token|client secret|webhook secret|password|credential|secret|token|key|account|project|tenant|organization|username|provider|vendor)\b|密码|凭据|密钥|令牌|账号|项目|租户|服务商|平台/i.test(text)) return "secret";
  if (context === "ssh-console" && !(control instanceof HTMLSelectElement) && /\b(?:private key|public key|authorized keys?|ssh key|passphrase|key password|ssh password|login password|ssh user|username|login|host|hostname|server|port)\b|私钥|公钥|口令|密码|账号|用户名|服务器|主机|端口/i.test(text)) return "ssh";
  if (tokens.some((token) => CARD_AUTOCOMPLETE.has(token)) || /\b(?:card number|cc num|cardholder|name on card|cvv|cvc|security code|billing address)\b|卡号|持卡人|安全码|账单地址/i.test(text) || context === "checkout" && /\b(?:expiration|expiry)\b|有效期|到期/i.test(text)) return "card";
  if (["login", "signup", "password-change", "password-reset", "otp"].includes(context) && semantics.role !== "other") return "login";
  if (tokens.some((token) => IDENTITY_AUTOCOMPLETE.has(token)) || /\b(?:first name|given name|middle name|last name|family name|surname|full name|e ?mail|phone|mobile|telephone|birthday|birth date|organization|company|employer|department|job title|website|street|address line [12]|city|province|postal|zip|country)\b|姓名|名字|姓氏|邮箱|电话|手机|城市|邮编|国家|部门|出生日期|公司/i.test(text)) return "identity";
  if (context === "profile" && /\b(?:state|region|suite|unit|apartment|position|team)\b|省|州|地区/i.test(text)) return "identity";
  return null;
}

function qualificationText(metadata: ReturnType<typeof getMetadata>) {
  return metadataText(metadata).replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ");
}

function isNonAutofillControl(control: SupportedControl, text = qualificationText(getMetadata(control))) {
  const words = new Set(text.toLowerCase().split(/[^a-z0-9]+/));
  return control instanceof HTMLInputElement && control.type === "search" ||
    Boolean(control.closest('[role="search"],search')) ||
    fieldPolicy.excludedWords.some((word) => words.has(word)) || fieldPolicy.excludedText.some((word) => text.includes(word));
}

const CARD_AUTOCOMPLETE = new Set(["cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc"]);

export function selectAutofillPageContext(fields: FieldDescriptor[]): PageContext {
  // Only fillable contexts participate in page-ready selection. Other form
  // clusters do not compete in one global scene classifier.
  if (fields.some((field) => field.context === "login")) return "login";
  if (fields.some((field) => field.context === "otp")) return "otp";
  return "unknown";
}

type SemanticCluster = {
  root: ParentNode;
  controls: SupportedControl[];
};

type CredentialContext = "login" | "signup" | "password-change" | "password-reset" | "otp";

export function analyzeControlSemantics(control: SupportedControl): ControlSemanticAnalysis {
  const cluster = semanticCluster(control);
  const role = credentialFieldRole(control, cluster);
  if (role === "otp" || isOtpDigitControl(control) && isSegmentedOtpCluster(cluster)) {
    return {
      context: "otp",
      role: "otp",
      confidence: "high",
      score: 240,
      competingScore: 0,
      reasons: ["field:otp"],
    };
  }

  const directText = metadataText(getMetadata(control));
  const clusterText = clusterSemanticText(cluster);
  if (/api[\s_-]*key|access[\s_-]*token|client[\s_-]*secret|webhook[\s_-]*secret|接口密钥|访问令牌/i.test(`${directText} ${clusterText}`)) {
    return { context: "developer-secret", role: "other", confidence: "high", score: 180, competingScore: 0, reasons: ["cluster:developer-secret"] };
  }
  if (/ssh|private[\s_-]*key|public[\s_-]*key|authorized[\s_-]*keys|私钥|公钥/i.test(`${directText} ${clusterText}`)) {
    return { context: "ssh-console", role: "other", confidence: "high", score: 180, competingScore: 0, reasons: ["cluster:ssh"] };
  }
  if (getMetadata(control).autocomplete.some((token) => token.startsWith("cc-")) || /card.?number|checkout|billing|payment|卡号|支付|账单/i.test(`${directText} ${clusterText}`)) {
    return { context: "checkout", role: "other", confidence: "high", score: 180, competingScore: 0, reasons: ["cluster:checkout"] };
  }
  const clusterHasPassword = cluster.controls.some((candidate) => candidate instanceof HTMLInputElement && candidate.type === "password");
  const clusterHasIdentityDetails = cluster.controls.some((candidate) => getMetadata(candidate).autocomplete.some((token) =>
    IDENTITY_AUTOCOMPLETE.has(token) && token !== "email" && token !== "tel",
  ));
  if (!clusterHasPassword && (clusterHasIdentityDetails || /profile|contact|shipping\s+address|姓名|联系|收货地址/i.test(clusterText))) {
    return { context: "profile", role: "other", confidence: "high", score: 150, competingScore: 0, reasons: ["cluster:identity-fields"] };
  }

  const scores = new Map<CredentialContext, number>();
  const reasons = new Map<CredentialContext, string[]>();
  const add = (context: CredentialContext, score: number, reason: string) => {
    scores.set(context, (scores.get(context) ?? 0) + score);
    const entries = reasons.get(context) ?? [];
    if (!entries.includes(reason)) entries.push(reason);
    reasons.set(context, entries);
  };
  const roles = cluster.controls.map((candidate) => credentialFieldRole(candidate, cluster));
  const accountCount = roles.filter((candidate) => candidate === "account").length;
  const currentCount = roles.filter((candidate) => candidate === "current-password").length;
  const newCount = roles.filter((candidate) => candidate === "new-password" || candidate === "confirmation-password").length;
  const confirmationCount = roles.filter((candidate) => candidate === "confirmation-password").length;
  const otpCount = roles.filter((candidate) => candidate === "otp").length;

  if (currentCount > 0 && newCount > 0) {
    add("password-change", 220, "structure:current-and-new-password");
  } else if (newCount > 0) {
    if (accountCount > 0) {
      add("signup", 85, "structure:account-and-new-password");
      add("password-reset", 25, "structure:new-password");
    } else {
      add("password-reset", confirmationCount > 0 ? 65 : 80, "structure:new-password-without-account");
      if (confirmationCount > 0) add("signup", 65, "structure:confirmed-new-password");
    }
  } else if (currentCount > 0) {
    add("login", accountCount > 0 ? 130 : 105, accountCount > 0 ? "structure:account-and-current-password" : "structure:current-password");
  } else if (accountCount > 0) {
    add("login", 55, "structure:account-only");
  }
  if (otpCount > 0 && currentCount === 0 && newCount === 0) add("otp", 100, "structure:otp-only");

  for (const path of semanticPaths(cluster, control.ownerDocument)) {
    if (LOGIN_ROUTE.test(path)) add("login", 70, "route:login");
    if (SIGNUP_ROUTE.test(path)) add("signup", 70, "route:signup");
    if (RESET_ROUTE.test(path)) add("password-reset", 70, "route:password-reset");
    if (CHANGE_PASSWORD_ROUTE.test(path)) add("password-change", 70, "route:password-change");
  }

  const submitText = semanticSubmitText(cluster);
  if (LOGIN_SEMANTICS.test(submitText)) add("login", 55, "submit:login");
  if (SIGNUP_SEMANTICS.test(submitText)) add("signup", 55, "submit:signup");
  if (RESET_SEMANTICS.test(submitText)) add("password-reset", 55, "submit:password-reset");
  if (CHANGE_PASSWORD_SEMANTICS.test(submitText)) add("password-change", 55, "submit:password-change");

  const headingText = semanticHeadingText(cluster);
  if (LOGIN_SEMANTICS.test(headingText)) add("login", 30, "heading:login");
  if (SIGNUP_SEMANTICS.test(headingText)) add("signup", 30, "heading:signup");
  if (RESET_SEMANTICS.test(headingText)) add("password-reset", 30, "heading:password-reset");
  if (CHANGE_PASSWORD_SEMANTICS.test(headingText)) add("password-change", 30, "heading:password-change");

  if (LOGIN_SEMANTICS.test(directText)) add("login", 20, "field:login-metadata");
  if (SIGNUP_SEMANTICS.test(directText)) add("signup", 20, "field:signup-metadata");
  if (RESET_SEMANTICS.test(directText)) add("password-reset", 20, "field:password-reset-metadata");

  const ranked = Array.from(scores.entries()).sort((left, right) => right[1] - left[1]);
  const winner = ranked[0];
  if (!winner || winner[1] < 45) {
    if (/profile|contact|address|姓名|联系|地址/i.test(clusterText)) {
      return { context: "profile", role: "other", confidence: "medium", score: 70, competingScore: winner?.[1] ?? 0, reasons: ["cluster:profile"] };
    }
    return { context: "unknown", role, confidence: "low", score: winner?.[1] ?? 0, competingScore: ranked[1]?.[1] ?? 0, reasons: winner ? reasons.get(winner[0]) ?? [] : [] };
  }
  const competingScore = ranked[1]?.[1] ?? 0;
  const margin = winner[1] - competingScore;
  const confidence: SemanticConfidence = winner[1] >= 110 && margin >= 35
    ? "high"
    : winner[1] >= 70 && margin >= 20
      ? "medium"
      : "low";
  return {
    context: winner[0],
    role,
    confidence,
    score: winner[1],
    competingScore,
    reasons: (reasons.get(winner[0]) ?? []).slice(0, 8),
  };
}

export function analyzeFormSemantics(control: SupportedControl): ControlSemanticAnalysis {
  const cluster = semanticCluster(control);
  const representative = cluster.controls.find((candidate) => credentialFieldRole(candidate, cluster) !== "otp") ?? control;
  return analyzeControlSemantics(representative);
}

export function credentialFieldRole(control: SupportedControl, cluster = semanticCluster(control)): CredentialFieldRole {
  const metadata = getMetadata(control);
  const directText = metadataText(metadata);
  if (metadata.autocomplete.includes("one-time-code") || OTP_METADATA.test(directText)) return "otp";

  if (control instanceof HTMLInputElement && control.type === "password") {
    if (metadata.autocomplete.includes("current-password") || CURRENT_PASSWORD_METADATA.test(directText)) return "current-password";
    if (CONFIRM_PASSWORD_METADATA.test(directText)) return "confirmation-password";
    if (metadata.autocomplete.includes("new-password") || NEW_PASSWORD_METADATA.test(directText)) return "new-password";

    const passwords = cluster.controls.filter((candidate): candidate is HTMLInputElement =>
      candidate instanceof HTMLInputElement && candidate.type === "password",
    );
    const index = passwords.indexOf(control);
    const confirmationIndex = passwords.findIndex((candidate) => CONFIRM_PASSWORD_METADATA.test(metadataText(getMetadata(candidate))));
    const explicitNewIndex = passwords.findIndex((candidate) => {
      const candidateMetadata = getMetadata(candidate);
      const candidateText = metadataText(candidateMetadata);
      return !CONFIRM_PASSWORD_METADATA.test(candidateText) &&
        (candidateMetadata.autocomplete.includes("new-password") || NEW_PASSWORD_METADATA.test(candidateText));
    });
    if (explicitNewIndex >= 0 && index >= 0) return index < explicitNewIndex ? "current-password" : "new-password";
    if (confirmationIndex > 0 && index >= 0) return index < confirmationIndex ? "new-password" : "confirmation-password";

    const intent = strongClusterIntent(cluster, control.ownerDocument);
    const hasAccount = cluster.controls.some((candidate) => candidate !== control && credentialFieldRoleWithoutStructure(candidate) === "account");
    if (passwords.length === 1 && hasAccount && intent === "signup") return "new-password";
    if (passwords.length === 1 && (intent === "password-reset" || intent === "password-change")) return "new-password";
    return "current-password";
  }

  return credentialFieldRoleWithoutStructure(control);
}

function credentialFieldRoleWithoutStructure(control: SupportedControl): CredentialFieldRole {
  const metadata = getMetadata(control);
  const text = qualificationText(metadata);
  if (isNonAutofillControl(control, text)) return "other";
  if (control instanceof HTMLInputElement && !["text", "email", "tel", "number", "password"].includes(control.type)) return "other";
  if (control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement) return "other";
  if (metadata.autocomplete.includes("one-time-code") || OTP_METADATA.test(text)) return "otp";
  if (metadata.autocomplete.includes("username") || metadata.autocomplete.includes("email")) return "account";
  if (control instanceof HTMLInputElement && (control.type === "email" || control.type === "tel")) return "account";
  if (/\b(?:user ?name|login|account|apple id|e ?mail|phone|mobile)\b|用户名|账号|邮箱|电话|手机/i.test(text)) return "account";
  return "other";
}

export function semanticCluster(control: SupportedControl): SemanticCluster {
  const explicit = control instanceof HTMLInputElement && control.form
    ? control.form
    : control.closest('form,[role="form"],dialog,[role="dialog"],fieldset');
  if (explicit) return { root: explicit, controls: semanticControls(explicit) };

  const treeRoot = control.getRootNode();
  let fallback: ParentNode = control;
  for (let ancestor = control.parentElement; ancestor && !ancestor.matches("body,html"); ancestor = ancestor.parentElement) {
    const controls = semanticControls(ancestor);
    if (controls.length === 0 || !controls.includes(control)) continue;
    fallback = ancestor;
    const passwordCount = controls.filter((candidate) => candidate instanceof HTMLInputElement && candidate.type === "password").length;
    const accountCount = controls.filter((candidate) => credentialFieldRoleWithoutStructure(candidate) === "account").length;
    const hasSubmit = semanticSubmitControls(ancestor).length > 0;
    if (passwordCount > 0 && (controls.length > 1 || accountCount > 0 || hasSubmit)) return { root: ancestor, controls };
    if (controls.length > 1 && ancestor.matches('section,article,main,[role="group"],[data-form],[class*="form"],[class*="login"],[class*="auth"]')) {
      return { root: ancestor, controls };
    }
  }
  return { root: fallback, controls: semanticControls(fallback) };
}

function semanticControls(root: ParentNode) {
  const controls = formControls(root);
  return controls
    .filter(isSemanticallyEligibleControl)
    .slice(0, 80);
}

function semanticPaths(cluster: SemanticCluster, document: Document) {
  const paths: string[] = [];
  const pagePath = document.defaultView?.location.pathname;
  if (pagePath) paths.push(limit(pagePath, 512));
  if (cluster.root instanceof HTMLFormElement) {
    const action = cluster.root.getAttribute("action");
    if (action) {
      try {
        paths.push(limit(new URL(action, document.defaultView?.location.href ?? "https://invalid.local/").pathname, 512));
      } catch {
        // Invalid actions are ignored; form classification remains local and
        // must not make a network request to resolve them.
      }
    }
  }
  return [...new Set(paths)];
}

function semanticSubmitControls(root: ParentNode) {
  return Array.from(root.querySelectorAll<HTMLElement>('button,input[type="submit"],input[type="button"],[role="button"]'))
    .filter(isSemanticallyVisible)
    .filter((candidate) => {
      if (candidate instanceof HTMLButtonElement) return candidate.type === "submit" || candidate.type === "button";
      return true;
    })
    .slice(0, 20);
}

function semanticSubmitText(cluster: SemanticCluster) {
  return semanticSubmitControls(cluster.root).map((candidate) => {
    if (candidate instanceof HTMLInputElement) return candidate.getAttribute("value") ?? candidate.getAttribute("aria-label") ?? "";
    return `${candidate.getAttribute("aria-label") ?? ""} ${candidate.textContent ?? ""}`;
  }).join(" ").slice(0, 1_000);
}

function semanticHeadingText(cluster: SemanticCluster) {
  const rootLabel = cluster.root instanceof Element
    ? `${cluster.root.getAttribute("aria-label") ?? ""} ${cluster.root.getAttribute("name") ?? ""}`
    : "";
  const headings = Array.from(cluster.root.querySelectorAll<HTMLElement>('h1,h2,h3,h4,legend,[role="heading"]'))
    .filter(isSemanticallyVisible)
    .map((candidate) => candidate.textContent ?? "")
    .join(" ");
  return `${rootLabel} ${headings}`.slice(0, 1_000);
}

function clusterSemanticText(cluster: SemanticCluster) {
  const fieldText = cluster.controls.map((candidate) => metadataText(getMetadata(candidate))).join(" ");
  return `${semanticHeadingText(cluster)} ${semanticSubmitText(cluster)} ${fieldText}`.slice(0, 2_000);
}

function strongClusterIntent(cluster: SemanticCluster, document: Document): CredentialContext | null {
  const matches = new Set<CredentialContext>();
  for (const path of semanticPaths(cluster, document)) {
    if (LOGIN_ROUTE.test(path)) matches.add("login");
    if (SIGNUP_ROUTE.test(path)) matches.add("signup");
    if (RESET_ROUTE.test(path)) matches.add("password-reset");
    if (CHANGE_PASSWORD_ROUTE.test(path)) matches.add("password-change");
  }
  const submitText = semanticSubmitText(cluster);
  if (LOGIN_SEMANTICS.test(submitText)) matches.add("login");
  if (SIGNUP_SEMANTICS.test(submitText)) matches.add("signup");
  if (RESET_SEMANTICS.test(submitText)) matches.add("password-reset");
  if (CHANGE_PASSWORD_SEMANTICS.test(submitText)) matches.add("password-change");
  return matches.size === 1 ? [...matches][0]! : null;
}

function isSegmentedOtpCluster(cluster: SemanticCluster) {
  const headingSuggestsOtp = OTP_METADATA.test(semanticHeadingText(cluster));
  const digitControls = cluster.controls.filter(isOtpDigitControl);
  const hasPassword = cluster.controls.some((candidate) => candidate instanceof HTMLInputElement && candidate.type === "password");
  return digitControls.length >= 4 && (headingSuggestsOtp || !hasPassword);
}

function isOtpDigitControl(control: SupportedControl) {
  return control instanceof HTMLInputElement && control.maxLength === 1 && ["text", "tel", "number"].includes(control.type);
}

function isSemanticallyEligibleControl(control: SupportedControl) {
  if (isInteractionDisabled(control) || !isSemanticallyVisible(control)) return false;
  if (control instanceof HTMLInputElement && !TEXT_INPUT_TYPES.has(control.type)) return false;
  const metadata = getMetadata(control);
  return !SENSITIVE_METADATA.test([metadata.label, metadata.name, metadata.id, metadata.placeholder].join(" "));
}

export function passwordFieldPurpose(control: Element): PasswordFieldPurpose | null {
  if (!(control instanceof HTMLInputElement) || control.type !== "password" || !isSupportedControl(control)) return null;
  const role = credentialFieldRole(control, semanticCluster(control));
  return role === "new-password" || role === "confirmation-password" ? "new" : "current";
}

export function isNewPasswordControl(control: Element) {
  return passwordFieldPurpose(control) === "new";
}

export function shouldPreserveExistingLoginAccount(target: Element) {
  return isControlElement(target) && classifyControl(target) === "login" && !isLoginAccountControl(target);
}

export function isEmailAccountControl(control: Element) {
  if (!isControlElement(control) || !isSupportedControl(control)) return false;
  const metadata = getMetadata(control);
  return metadata.autocomplete.includes("email") ||
    control instanceof HTMLInputElement && control.type === "email" ||
    /\be[\s_-]?mail\b|电子邮件|邮箱/i.test(metadataText(metadata));
}

export function passwordFieldGroup(control: HTMLInputElement) {
  if (control.form) return supportedPasswordControls(control.form);

  const root = control.getRootNode();
  for (let container = control.parentElement; container; container = container.parentElement) {
    const controls = supportedPasswordControls(container).filter((candidate) => candidate.form === null && candidate.getRootNode() === root);
    if (controls.length === 2 || (controls.length > 0 && container.matches('dialog,[role="dialog"],[role="form"]'))) return controls;
  }
  if (root instanceof ShadowRoot) {
    const controls = supportedPasswordControls(root).filter((candidate) => candidate.form === null);
    if (controls.length === 2) return controls;
  }
  return [control];
}

export function hasLoginFields(fields: FieldDescriptor[]) {
  return fields.some(isLoginFieldDescriptor);
}

export function loginFormSignature(fields: FieldDescriptor[]) {
  return fields
    .filter(isLoginFieldDescriptor)
    .map((field) => [field.control, field.inputType ?? "", field.autocomplete.join(","), field.name, field.id].join(":"))
    .join("|")
    .slice(0, 512);
}

function isLoginFieldDescriptor(field: FieldDescriptor) {
  return field.inputType === "password" || field.context === "otp" ||
    field.autocomplete.some((token) => ["username", "current-password", "one-time-code"].includes(token)) ||
    OTP_METADATA.test([field.label, field.name, field.id, field.placeholder].join(" "));
}

export async function applyAssignments({
  message,
  documentId,
  fields,
  currentOrigin,
  currentDocumentId,
}: {
  message: Extract<ContentMessage, { kind: "vaultmesh.apply-assignments" }>;
  documentId: string;
  fields: Map<string, SupportedControl>;
  currentOrigin: string;
  currentDocumentId?: () => string;
}) {
  const assignmentIsCurrent = () =>
    message.documentId === documentId &&
    (currentDocumentId == null || currentDocumentId() === documentId) &&
    message.frameOrigin === currentOrigin &&
    Date.parse(message.expiresAt) > Date.now();
  if (!assignmentIsCurrent()) {
    return { status: "stale-document" as const, results: [] };
  }

  // Login pages commonly list the password assignment first even though users
  // expect to see the account entered before the password. Keep all other
  // assignments stable while always moving password controls to the end.
  const assignments = [...message.assignments].sort((left, right) =>
    assignmentPriority(fields.get(left.handle)) - assignmentPriority(fields.get(right.handle)),
  );
  const results: Array<{ handle: string; status: string }> = [];

  if (message.clearBeforeFill) {
    let clearedAny = false;
    const controlsToClear = message.selectedItem
      ? Array.from(fields.values()).filter((control) => classifyControl(control) === message.selectedItem!.kind)
      : assignments.flatMap((assignment) => {
          const control = fields.get(assignment.handle);
          return control ? [control] : [];
        });
    for (const control of controlsToClear) {
      if (!assignmentIsCurrent()) return { status: "stale-document" as const, results };
      if (!control.isConnected || !hasValue(control)) continue;
      if (!await waitForControlReady(control, message.expiresAt, assignmentIsCurrent)) {
        if (!assignmentIsCurrent()) return { status: "stale-document" as const, results };
        continue;
      }
      if (!assignValue(control, "")) continue;
      dispatchInput(control, null, "deleteContentBackward");
      control.dispatchEvent(new Event("change", { bubbles: true }));
      clearedAny = true;
    }
    if (clearedAny) await delay(FIELD_DELAY_MS);
  }

  for (const assignment of assignments) {
    if (!assignmentIsCurrent()) return { status: "stale-document" as const, results };
    const control = fields.get(assignment.handle);
    if (!control || !control.isConnected) {
      results.push({ handle: assignment.handle, status: "missing" as const });
      continue;
    }
    if (!message.clearBeforeFill && !assignment.overwrite && hasValue(control)) {
      results.push({ handle: assignment.handle, status: "skipped-non-empty" as const });
      continue;
    }
    if (!await waitForControlReady(control, message.expiresAt, assignmentIsCurrent)) {
      if (!assignmentIsCurrent()) return { status: "stale-document" as const, results };
      results.push({ handle: assignment.handle, status: "not-ready" as const });
      continue;
    }

    if (control instanceof HTMLSelectElement) {
      if (!assignValue(control, assignment.value)) {
        results.push({ handle: assignment.handle, status: "invalid-select-option" as const });
        continue;
      }
      dispatchInput(control);
    } else if (!await typeValue(control, assignment.value, message.expiresAt, assignmentIsCurrent)) {
      if (!assignmentIsCurrent()) return { status: "stale-document" as const, results };
      results.push({ handle: assignment.handle, status: "invalid-value" as const });
      continue;
    }

    control.dispatchEvent(new Event("change", { bubbles: true }));
    results.push({ handle: assignment.handle, status: "filled" as const });
    if (!(control instanceof HTMLInputElement && control.maxLength === 1)) await delay(FIELD_DELAY_MS);
  }

  return { status: "completed" as const, results };
}

function assignmentPriority(control: SupportedControl | undefined) {
  return control instanceof HTMLInputElement && control.type === "password" ? 1 : 0;
}

async function waitForControlReady(control: SupportedControl, expiresAt: string, assignmentIsCurrent: () => boolean = () => true) {
  const deadline = Math.min(Date.parse(expiresAt), Date.now() + CONTROL_READY_TIMEOUT_MS);
  while (assignmentIsCurrent() && Date.now() < deadline) {
    if (isControlReady(control)) return true;
    await delay(CONTROL_READY_POLL_MS);
  }
  return assignmentIsCurrent() && isControlReady(control);
}

function isControlReady(control: SupportedControl) {
  return control.isConnected && isSupportedControl(control);
}

async function typeValue(control: Exclude<SupportedControl, HTMLSelectElement>, value: string, expiresAt: string, assignmentIsCurrent: () => boolean = () => true) {
  if (!assignmentIsCurrent()) return false;
  control.focus({ preventScroll: true });
  assignValue(control, "");
  let typed = "";
  for (const character of Array.from(value)) {
    if (!assignmentIsCurrent() || !isControlReady(control) || Date.parse(expiresAt) <= Date.now()) break;
    typed += character;
    assignValue(control, typed);
    dispatchInput(control, character);
    await delay(CHARACTER_DELAY_MS);
  }
  return isNativeControl(control) ? control.value === value : control.textContent === value;
}

function dispatchInput(control: SupportedControl, data: string | null = null, inputType = "insertText") {
  const InputEventConstructor = control.ownerDocument.defaultView?.InputEvent;
  const event = InputEventConstructor
    ? new InputEventConstructor("input", { bubbles: true, inputType, data })
    : new Event("input", { bubbles: true });
  control.dispatchEvent(event);
}

function delay(milliseconds: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

function isHttpOrigin(value: string) {
  return value.startsWith("http://") || value.startsWith("https://");
}

function isSupportedControl(control: SupportedControl) {
  if (isInteractionDisabled(control) || !isVisible(control) || isNonAutofillControl(control)) {
    return false;
  }
  if (control instanceof HTMLInputElement && !TEXT_INPUT_TYPES.has(control.type)) {
    return false;
  }

  const metadata = getMetadata(control);
  return !SENSITIVE_METADATA.test([metadata.label, metadata.name, metadata.id, metadata.placeholder].join(" "));
}

function buildDescriptor(control: SupportedControl): FieldDescriptor | null {
  const metadata = getMetadata(control);
  const handle = createUuid();
  const base = {
    handle,
    isEmpty: !hasValue(control),
    autocomplete: metadata.autocomplete,
    label: metadata.label,
    name: metadata.name,
    id: metadata.id,
    placeholder: metadata.placeholder,
    context: analyzeControlSemantics(control).context,
  };

  if (control instanceof HTMLInputElement) {
    return { ...base, control: "input", inputType: control.type, ...(control.maxLength > 0 ? { maxLength: control.maxLength } : {}) };
  }
  if (control instanceof HTMLTextAreaElement) {
    return { ...base, control: "textarea" };
  }
  if (!(control instanceof HTMLSelectElement)) return { ...base, control: "contenteditable" };
  return {
    ...base,
    control: "select",
    options: Array.from(control.options)
      .slice(0, MAX_OPTIONS)
      .map((option) => ({ value: limit(option.value, 160), text: limit(option.textContent ?? "", 160) })),
  };
}

function getMetadata(control: SupportedControl) {
  return {
    autocomplete: (control.getAttribute("autocomplete") ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 8),
    label: limit(getLabels(control).join(" "), 240),
    name: limit(control.getAttribute("name") ?? "", 160),
    id: limit(control.id, 160),
    placeholder: limit(control.getAttribute("placeholder") ?? "", 160),
  };
}

function isLoginAccountControl(control: SupportedControl) {
  if (control instanceof HTMLInputElement && control.type === "password") return false;
  const metadata = getMetadata(control);
  return metadata.autocomplete.some((token) => token === "username" || token === "email") ||
    control instanceof HTMLInputElement && (control.type === "email" || control.type === "tel") ||
    /user(name)?|login|account|e-?mail|phone|mobile|用户名|账号|邮箱|电话|手机/i.test(metadataText(metadata));
}

function metadataText(metadata: ReturnType<typeof getMetadata>) {
  return [metadata.label, metadata.name, metadata.id, metadata.placeholder].join(" ");
}

function supportedPasswordControls(root: ParentNode) {
  return Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter(isSupportedControl);
}

function getLabels(control: SupportedControl) {
  const labels = Array.from(control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement || control instanceof HTMLSelectElement ? control.labels ?? [] : []).map((label) => label.textContent ?? "");
  const ariaLabel = control.getAttribute("aria-label");
  if (ariaLabel) {
    labels.push(ariaLabel);
  }
  const labelledBy = control.getAttribute("aria-labelledby");
  if (labelledBy) {
    const root = control.getRootNode();
    for (const id of labelledBy.split(/\s+/)) {
      const labelledElement = root instanceof ShadowRoot ? root.getElementById(id) : control.ownerDocument.getElementById(id);
      labels.push(labelledElement?.textContent ?? "");
    }
  }
  return labels.filter(Boolean).map((label) => limit(label, 160));
}

function isVisible(control: SupportedControl) {
  return isSemanticallyVisible(control) && control.getClientRects().length > 0;
}

function isSemanticallyVisible(control: HTMLElement) {
  const view = control.ownerDocument.defaultView;
  if (!view) return false;
  for (let element: Element | null = control; element; element = composedParentElement(element)) {
    const style = view.getComputedStyle(element);
    if (
      element.hasAttribute("hidden") ||
      element.hasAttribute("inert") ||
      element.getAttribute("aria-hidden")?.toLowerCase() === "true" ||
      style.contentVisibility === "hidden" ||
      Number.parseFloat(style.opacity) <= 0.01
    ) return false;
    if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
    if (element !== control && clipsCollapsedContent(style)) return false;
  }
  return true;
}

function isInteractionDisabled(control: SupportedControl) {
  return (isNativeControl(control) && control.disabled) ||
    ((control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement) && control.readOnly) ||
    control.matches(":disabled") ||
    control.getAttribute("aria-readonly")?.toLowerCase() === "true" ||
    control.getAttribute("aria-disabled")?.toLowerCase() === "true";
}

function composedParentElement(element: Element): Element | null {
  if (element.parentElement) return element.parentElement;
  const root = element.getRootNode();
  return root instanceof ShadowRoot ? root.host : null;
}

function clipsCollapsedContent(style: CSSStyleDeclaration) {
  const clipsVertically = style.overflow === "hidden" || style.overflow === "clip" || style.overflowY === "hidden" || style.overflowY === "clip";
  const clipsHorizontally = style.overflow === "hidden" || style.overflow === "clip" || style.overflowX === "hidden" || style.overflowX === "clip";
  return (clipsVertically && Number.parseFloat(style.height) === 0) || (clipsHorizontally && Number.parseFloat(style.width) === 0);
}

function hasValue(control: SupportedControl) {
  return isNativeControl(control) ? control.value.length > 0 : (control.textContent ?? "").length > 0;
}

function assignValue(control: SupportedControl, value: string) {
  if (!isNativeControl(control)) {
    control.textContent = value;
    return control.textContent === value;
  }
  const prototype = control instanceof HTMLInputElement
    ? HTMLInputElement.prototype
    : control instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLSelectElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
  if (!setter) return false;
  setter.call(control, value);
  return !(control instanceof HTMLSelectElement) || control.value === value;
}

export function formControls(root: ParentNode): SupportedControl[] {
  if (root instanceof HTMLFormElement) {
    // Include controls associated by form= even when they are outside the form.
    return [...new Set([...composedControls(root), ...Array.from(root.elements).filter(isControlElement)])]
      .filter((control) => !isNativeControl(control) || !control.form || control.form === root);
  }
  const descendants = composedControls(root);
  return root instanceof Element && isControlElement(root) ? [root, ...descendants] : descendants;
}

function composedControls(root: ParentNode) {
  const controls: SupportedControl[] = [];
  const roots: ParentNode[] = [root];
  for (let index = 0; index < roots.length; index += 1) {
    const current = roots[index]!;
    controls.push(...current.querySelectorAll<SupportedControl>('input, textarea, select, [contenteditable]:not([contenteditable="false"])'));
    for (const element of current.querySelectorAll<HTMLElement>("*")) {
      if (element.matches("[data-vaultmesh-autofill],[data-vaultmesh-autofill-trigger]")) continue;
      const shadowRoot = accessibleShadowRoot(element);
      if (shadowRoot) roots.push(shadowRoot);
    }
  }
  return controls;
}

/**
 * Chromium and Firefox expose closed component roots to extension content
 * scripts through their DOM extension API. Fall back to the normal open-root
 * property so the discovery code remains portable and straightforward to test.
 */
export function accessibleShadowRoot(element: Element): ShadowRoot | null {
  if (element.shadowRoot) return element.shadowRoot;
  const globals = globalThis as typeof globalThis & {
    browser?: { dom?: { openOrClosedShadowRoot?: (target: Element) => ShadowRoot | null } };
    chrome?: { dom?: { openOrClosedShadowRoot?: (target: Element) => ShadowRoot | null } };
  };
  const resolver = globals.browser?.dom?.openOrClosedShadowRoot ?? globals.chrome?.dom?.openOrClosedShadowRoot;
  if (!resolver) return null;
  try {
    return resolver(element);
  } catch {
    return null;
  }
}

function isNativeControl(control: SupportedControl): control is NativeControl {
  return control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement || control instanceof HTMLSelectElement;
}

function isControlElement(control: Element): control is SupportedControl {
  const contentEditable = control instanceof HTMLElement ? control.getAttribute("contenteditable")?.toLowerCase() : null;
  return isNativeControl(control as SupportedControl) || control instanceof HTMLElement &&
    (control.isContentEditable || contentEditable != null && contentEditable !== "false");
}

function limit(value: string, maximum: number) {
  return value.replace(/\s+/g, " ").trim().slice(0, maximum);
}

const IDENTITY_AUTOCOMPLETE = new Set([
  "name", "given-name", "additional-name", "family-name", "email", "tel", "organization", "organization-title", "url",
  "bday", "address-line1", "address-line2", "address-level1", "address-level2", "postal-code", "country", "country-name",
]);
