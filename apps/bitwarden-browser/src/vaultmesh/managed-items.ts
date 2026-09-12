import { z } from "zod";
import * as model from "./vendor/model-contracts";

export const ManagedKindSchema = z.enum(["card", "identity", "ssh", "secret"]);
export type ManagedKind = z.infer<typeof ManagedKindSchema>;
export const MANAGED_ITEMS = {
  card: { label: "支付卡", prefix: "cards", input: model.PaymentCardInputSchema, update: model.PaymentCardUpdateSchema,
    summary: model.PaymentCardSummarySchema, detail: model.PaymentCardDetailSchema,
    trash: model.PaymentCardTrashSummarySchema, history: model.PaymentCardRevisionSummarySchema,
    copy: ["number", "security-code", "pin"] },
  identity: { label: "身份资料", prefix: "identities", input: model.IdentityInputSchema, update: model.IdentityUpdateSchema,
    summary: model.IdentitySummarySchema, detail: model.IdentityDetailSchema,
    trash: model.IdentityTrashSummarySchema, history: model.IdentityRevisionSummarySchema, copy: [] },
  ssh: { label: "SSH", prefix: "ssh", input: model.SshCredentialInputSchema, update: model.SshCredentialUpdateSchema,
    summary: model.SshCredentialSummarySchema, detail: model.SshCredentialDetailSchema,
    trash: model.SshCredentialTrashSummarySchema, history: model.SshCredentialRevisionSummarySchema,
    copy: ["password", "public-key", "private-key", "key-passphrase"] },
  secret: { label: "服务密钥", prefix: "secrets", input: model.SecretItemInputSchema, update: model.SecretItemUpdateSchema,
    summary: model.SecretItemSummarySchema, detail: model.SecretItemDetailSchema,
    trash: null as null, history: null as null, copy: ["value"] },
} as const;

const target = { kind: ManagedKindSchema, id: z.uuid() };
const recoverable = z.enum(["card", "identity", "ssh"]);
export const ManagedCommandSchema = z.discriminatedUnion("verb", [
  z.object({ verb: z.literal("list"), kind: ManagedKindSchema }).strict(),
  z.object({ verb: z.literal("detail"), ...target }).strict(),
  z.object({ verb: z.literal("save"), kind: ManagedKindSchema, input: z.record(z.string(), z.unknown()) }).strict(),
  z.object({ verb: z.literal("delete"), ...target, confirmed: z.literal(true) }).strict(),
  z.object({ verb: z.literal("copy"), ...target, field: z.string().max(32), masterPassword: z.string().min(8).max(1024).optional() }).strict(),
  z.object({ verb: z.literal("trash"), kind: recoverable }).strict(),
  z.object({ verb: z.literal("history"), kind: recoverable, id: z.uuid() }).strict(),
  z.object({ verb: z.literal("restore-trash"), kind: recoverable, trashId: z.uuid(), itemId: z.uuid(), confirmed: z.literal(true) }).strict(),
  z.object({ verb: z.literal("purge"), kind: recoverable, trashId: z.uuid(), confirmed: z.literal(true) }).strict(),
  z.object({ verb: z.literal("empty-trash"), kind: recoverable, confirmed: z.literal(true) }).strict(),
  z.object({ verb: z.literal("restore-history"), kind: recoverable, itemId: z.uuid(), revisionId: z.uuid(), confirmed: z.literal(true) }).strict(),
  z.object({ verb: z.literal("clear-history"), kind: recoverable, id: z.uuid(), confirmed: z.literal(true) }).strict(),
]).superRefine((command, context) => {
  const definition = MANAGED_ITEMS[command.kind];
  if (command.verb === "copy" && !(definition.copy as readonly string[]).includes(command.field)) {
    context.addIssue({ code: "custom", message: "Unsupported copy field" });
  }
  if (command.verb === "save") {
    const parsed = (command.input.id ? definition.update : definition.input).strict().safeParse(command.input);
    if (!parsed.success) context.addIssue({ code: "custom", message: "Invalid item input" });
    for (const [flag, field] of [["clearSecurityCode", "securityCode"], ["clearPin", "pin"], ["clearPassword", "password"],
      ["clearPublicKey", "publicKey"], ["clearPrivateKey", "privateKey"], ["clearKeyPassphrase", "keyPassphrase"]]) {
      if (command.input[flag] && command.input[field] != null) context.addIssue({ code: "custom", message: "Conflicting replacement" });
    }
  }
});
export type ManagedCommand = z.infer<typeof ManagedCommandSchema>;
export type ManagedRow = Record<string, unknown> & { title: string; id?: string; itemId?: string; trashId?: string; revisionId?: string };
export type ManagedResult = ManagedRow | ManagedRow[] | { clearsAt: number } | null;
export const managedMutation = (command: ManagedCommand) => !["list", "detail", "trash", "history"].includes(command.verb);
export const managedConfirmation = (command: ManagedCommand) => ["delete", "purge", "empty-trash", "restore-history", "clear-history"].includes(command.verb);

/** Only this closed mapping can select an RPC operation. No free-form RPC route is exposed to a popup. */
export function managedRequest(command: ManagedCommand): { operation: string; input: Record<string, unknown> } {
  const c = ManagedCommandSchema.parse(command);
  const definition = MANAGED_ITEMS[c.kind];
  let suffix: string;
  let input: Record<string, unknown> = {};
  switch (c.verb) {
    case "list": suffix = "list"; break;
    case "detail": suffix = "detail"; input = { id: c.id }; break;
    case "save": suffix = c.input.id ? "update" : "add"; input = (c.input.id ? definition.update : definition.input).strict().parse(c.input); break;
    case "delete": suffix = "delete"; input = { id: c.id }; break;
    case "copy": suffix = `copy-${c.field}`; input = { id: c.id, masterPassword: c.masterPassword ?? null }; break;
    case "trash": suffix = "trash.list"; break;
    case "history": suffix = "history.list"; input = { id: c.id }; break;
    case "restore-trash": suffix = "trash.restore"; input = { trashId: c.trashId }; break;
    case "purge": suffix = "trash.purge"; input = { trashId: c.trashId }; break;
    case "empty-trash": suffix = "trash.empty"; break;
    case "restore-history": suffix = "history.restore"; input = { itemId: c.itemId, revisionId: c.revisionId }; break;
    case "clear-history": suffix = "history.clear"; input = { id: c.id }; break;
  }
  return { operation: `${definition.prefix}.${suffix}`, input };
}

export function parseManagedResult(command: ManagedCommand, raw: unknown): ManagedResult {
  const definition = MANAGED_ITEMS[command.kind];
  switch (command.verb) {
    case "list": return z.array(definition.summary).max(10000).parse(raw).filter((row) => !("isPasskey" in row && row.isPasskey));
    case "detail": {
      const value = definition.detail.parse(raw);
      if (value.id !== command.id || ("isPasskey" in value && value.isPasskey)) throw new Error("invalid-broker-response");
      return value;
    }
    case "save": case "restore-history": case "restore-trash": {
      const value = definition.summary.parse(raw);
      const expected = command.verb === "save" ? command.input.id : command.itemId;
      if ((expected && value.id !== expected) || ("isPasskey" in value && value.isPasskey)) throw new Error("execution-unknown");
      return value;
    }
    case "copy": return z.object({ clearsAt: z.number().int().nonnegative() }).strict().parse(raw);
    case "trash": return z.array(MANAGED_ITEMS[command.kind].trash).max(10000).parse(raw);
    case "history": {
      const rows = z.array(MANAGED_ITEMS[command.kind].history).max(10000).parse(raw);
      if (rows.some((row) => row.itemId !== command.id)) throw new Error("invalid-broker-response");
      return rows;
    }
    default: if (raw !== null) z.object({}).strict().parse(raw); return null;
  }
}

/** Clear all transient item/password/PIN material, including rejected unknown fields. */
export function clearManagedSecrets(value: unknown): void {
  const pending = [value];
  const seen = new WeakSet<object>();
  while (pending.length) {
    const current = pending.pop();
    if (!current || typeof current !== "object" || seen.has(current)) continue;
    seen.add(current);
    for (const [key, entry] of Object.entries(current)) {
      if (["masterPassword", "password", "cardNumber", "securityCode", "pin", "publicKey", "privateKey", "keyPassphrase", "secret", "currentPassword", "newPassword"].includes(key)) {
        (current as Record<string, unknown>)[key] = typeof entry === "string" ? "" : null;
      } else if (entry && typeof entry === "object") pending.push(entry);
    }
  }
}
