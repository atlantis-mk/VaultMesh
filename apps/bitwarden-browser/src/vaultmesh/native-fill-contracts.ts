import { z } from "zod";
import type AutofillPageDetails from "../autofill/models/autofill-page-details";
import fieldPolicy from "./vendor/autofill-field-policy.json";
import { EmailCandidateSchema } from "./email-otp";
export { NativeLoginPlanSchema } from "./vendor/browser-native-login-plan";

export const FILL_COLLECT = "vaultmesh.native-fill.collect";
export const FILL_APPLY = "vaultmesh.native-fill.apply";
export const FILL_CANCEL = "vaultmesh.native-fill.cancel";
export const FILL_CHECK = "vaultmesh.native-fill.check";
export const FILL_CANDIDATES = "vaultmesh.native-fill.candidates";
export const FILL_SELECT = "vaultmesh.native-fill.select";
export const FILL_AUTOMATIC = "vaultmesh.native-fill.automatic";
export const FILL_LIFETIME = 30_000;
const text = z.string().max(2_048);
export const FieldMetadataSchema = z.object({
  opid: z.string().min(1).max(128), handle: z.string().uuid(), empty: z.boolean(),
  elementNumber: z.number().int().nonnegative(), viewable: z.boolean(),
  tagName: text, type: text, htmlID: text, htmlName: text, htmlClass: text,
  title: text, placeholder: text, autoCompleteType: text,
  "label-left": text, "label-right": text, "label-top": text, "label-tag": text,
  "label-aria": text, "label-data": text, "aria-describedby": text,
  disabled: z.boolean(), readonly: z.boolean(),
  form: text.nullable(), maxLength: z.number().int().nullable(),
  selectInfo: z.object({ options: z.array(z.tuple([z.string().max(160), z.string().max(160)])).max(200) }).strict().optional(),
  context: z.enum(["unknown", "login", "otp"]).default("unknown"),
}).strict();
const FormMetadataSchema = z.object({
  opid: text, htmlName: text, htmlID: text, htmlAction: text, htmlMethod: text,
  htmlClass: text, htmlAncestorHeadings: z.array(text).max(20),
}).strict();
export const CollectedPageSchema = z.object({
  requestId: z.string().uuid(), documentId: z.string().uuid(),
  url: z.string().url().max(8_192), expiresAt: z.string().datetime(),
  fields: z.array(FieldMetadataSchema).max(300),
  forms: z.record(z.string().max(128), FormMetadataSchema),
}).strict();
export type CollectedPage = z.infer<typeof CollectedPageSchema>;
export type FieldMetadata = z.infer<typeof FieldMetadataSchema>;
export const NativeCandidateSchema = z.object({
  id: z.string().uuid(), kind: z.enum(["login", "card", "identity", "ssh", "secret"]), title: z.string().max(1024), subtitle: z.string().max(2048),
  matchScope: z.string().max(64).default(""), autofillOnPageLoad: z.boolean().default(false), masterPasswordReprompt: z.boolean().default(false),
}).strict();
export const NativeCandidatesSchema = z.object({ candidates: z.array(NativeCandidateSchema).max(200), emailOtpCandidates: z.array(EmailCandidateSchema).max(20).optional() }).strict();
export type NativeCandidate = z.infer<typeof NativeCandidateSchema>;

export const AssignmentSchema = z.object({
  kind: z.literal("vaultmesh.approved-fill"), requestId: z.string().uuid(),
  tabId: z.number().int().nonnegative(), topOrigin: z.string().url(), expiresAt: z.string().datetime(),
  selectedItem: z.object({ kind: z.enum(["login", "card", "identity", "ssh", "secret"]), id: z.string().uuid(), title: z.string().max(1_024) }).strict(),
  frames: z.array(z.object({
    frameId: z.number().int().nonnegative(), documentId: z.string().uuid(), frameOrigin: z.string().url(),
    assignments: z.array(z.object({ handle: z.string().uuid(), value: z.string().min(1).max(40_000), overwrite: z.boolean() }).strict()).min(1).max(300),
  }).strict()).length(1),
}).strict();
export type Assignment = z.infer<typeof AssignmentSchema>;
export const EmailAssignmentSchema = AssignmentSchema.omit({ selectedItem: true });

export function clearAssignment(value: unknown): void {
  if (!value || typeof value !== "object" || !("frames" in value) || !Array.isArray(value.frames)) return;
  for (const frame of value.frames) {
    if (!frame || !Array.isArray(frame.assignments)) continue;
    for (const entry of frame.assignments) if (entry && typeof entry === "object") entry.value = "";
  }
}

/** An empty-bit projection. Never spread an upstream field containing `value`. */
export function projectField(field: AutofillPageDetails["fields"][number], handle: string): FieldMetadata {
  const strings = ["tagName", "type", "htmlID", "htmlName", "htmlClass", "title", "placeholder", "autoCompleteType",
    "label-left", "label-right", "label-top", "label-tag", "label-aria", "label-data", "aria-describedby"];
  return FieldMetadataSchema.parse({
    ...Object.fromEntries(strings.map((key) => [key, typeof field[key] === "string" ? field[key].slice(0, 2_048) : ""])),
    opid: field.opid, handle, empty: !field.value, elementNumber: field.elementNumber,
    viewable: !!field.viewable, disabled: !!field.disabled, readonly: !!field.readonly,
    form: typeof field.form === "string" ? field.form : null,
    maxLength: Number.isInteger(field.maxLength) ? field.maxLength : null,
    ...(field.selectInfo ? { selectInfo: { options: field.selectInfo.options.slice(0, 200).map(([label, value]: [string, string]) => [label.slice(0, 160), value.slice(0, 160)]) } } : {}),
  });
}

export function nativePage(page: CollectedPage): AutofillPageDetails {
  return { url: page.url, documentUrl: page.url, title: "", collectedTimestamp: Date.now(), forms: page.forms,
    fields: page.fields.map(({ handle: _handle, empty, context: _context, ...field }) => ({ ...field, tabindex: null as string | null, value: empty ? "" : "nonempty" })),
  } as AutofillPageDetails;
}

/** Shared exclusion guard only; Bitwarden still decides which fields match a Login. */
export function excludedMetadata(value: string): boolean {
  const words = value.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^\p{L}\p{N}]+/u);
  return fieldPolicy.excludedWords.some((word) => words.includes(word))
    || fieldPolicy.excludedText.some((word) => value.includes(word));
}

export function fillableLoginInput(element: HTMLInputElement): boolean {
  return element.isConnected && !element.disabled && !element.readOnly && !element.closest("[inert]")
    && ["text", "email", "tel", "password", "number"].includes(element.type)
    && !/(?:^|\s)new-password(?:\s|$)/.test(element.autocomplete)
    && !excludedMetadata([element.id, element.name, element.title, element.placeholder,
      element.getAttribute("aria-label") ?? "", element.autocomplete].join(" "));
}

export type FillControl = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
export function isFillControl(element: unknown): element is FillControl {
  return element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement;
}
export function fillableControl(element: FillControl): boolean {
  if (element instanceof HTMLInputElement && element.type !== "month") return fillableLoginInput(element);
  return element.isConnected && !element.disabled && !("readOnly" in element && element.readOnly)
    && !element.closest("[inert]") && !excludedMetadata([element.id, element.name, element.title,
      element.getAttribute("placeholder") ?? "", element.getAttribute("aria-label") ?? "", element.autocomplete].join(" "));
}
