import { z } from "zod";
import * as model from "./vendor/model-contracts";
const empty = z.object({}).strict();
const operation = z.enum(["pin.status", "pin.enable", "pin.disable", "pin.unlock", "biometric.status", "biometric.enable", "biometric.disable", "biometric.unlock",
  "security.settings.get", "security.settings.update", "browser.pairing.status", "browser.pairing.revoke", "password.health", "browser.fill.history", "vault.unlock-history", "vault.create", "vault.change-password"]);
const tool = (input: z.ZodType, result: z.ZodType, unlocked = true, mutation = true, confirmation = false) => ({ input, result, unlocked, mutation, confirmation });
export const SECURITY_TOOLS = {
  "vault.create": tool(model.MasterPasswordInputSchema.strict(), model.VaultOperationResultSchema, false, true, true),
  "vault.change-password": tool(model.ChangeMasterPasswordSchema.strict(), empty, true, true, true),
  "pin.status": tool(empty, model.PinStatusSchema, false, false),
  "pin.enable": tool(model.PinSetupSchema.strict(), model.PinStatusSchema),
  "pin.disable": tool(empty, model.PinStatusSchema),
  "pin.unlock": tool(model.PinInputSchema.strict(), model.VaultOperationResultSchema, false),
  "biometric.status": tool(empty, model.BiometricStatusSchema, false, false),
  "biometric.enable": tool(empty, model.BiometricStatusSchema),
  "biometric.disable": tool(empty, model.BiometricStatusSchema),
  "biometric.unlock": tool(empty, model.VaultOperationResultSchema, false),
  "security.settings.get": tool(empty, model.SecuritySettingsSchema, true, false),
  "security.settings.update": tool(model.SecuritySettingsSchema, model.SecuritySettingsSchema),
  "browser.pairing.status": tool(empty, z.object({ paired: z.boolean() }), false, false),
  "browser.pairing.revoke": tool(empty, z.object({ paired: z.literal(false) }), false, true, true),
  "password.health": tool(empty, model.PasswordHealthReportSchema, true, false),
  "browser.fill.history": tool(empty, z.array(model.FillEventSchema).max(1000), true, false),
  "vault.unlock-history": tool(empty, z.array(model.UnlockEventSchema).max(1000), false, false),
} as const;
export const SecurityCommandSchema = z.object({ operation, input: z.record(z.string(), z.unknown()), confirmed: z.literal(true).optional() }).strict()
  .superRefine((command, context) => {
    const definition = SECURITY_TOOLS[command.operation];
    if (!definition.input.safeParse(command.input).success || definition.confirmation && !command.confirmed) {
      context.addIssue({ code: "custom", message: "Invalid security operation" });
    }
  });
export type SecurityCommand = z.infer<typeof SecurityCommandSchema>;
