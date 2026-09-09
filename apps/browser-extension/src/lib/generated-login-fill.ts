import { applyAssignments, discoverFields, documentHttpOrigin, isNewPasswordControl, passwordFieldGroup, semanticCluster, formControls } from "@/lib/form-discovery";
import type { GeneratedLogin } from "@/lib/generated-credentials";
import { createUuid } from "@/lib/uuid";

type DocumentIdSource = string | (() => string);

export async function fillGeneratedLogin(document: Document, documentId: DocumentIdSource, login: GeneratedLogin, target?: HTMLElement) {
  const assignedDocumentId = resolveDocumentId(documentId);
  const { handles, descriptors } = discoverFields(document);
  const seed = target ?? [...handles.values()].find((control) => isNewPasswordControl(control));
  const container = seed ? semanticCluster(seed).root : null;
  const scopedControls = container ? new Set(formControls(container)) : null;
  const scopedDescriptors = scopedControls
    ? descriptors.filter((field) => {
        const control = handles.get(field.handle);
        return Boolean(control && scopedControls.has(control));
      })
    : descriptors;
  const passwordFields = scopedDescriptors.filter((field) => {
    const control = handles.get(field.handle);
    return control instanceof HTMLInputElement && control.type === "password" && isNewPasswordControl(control);
  });
  const firstPasswordIndex = passwordFields.length > 0 ? scopedDescriptors.indexOf(passwordFields[0]!) : scopedDescriptors.length;
  const targetUsername = target
    ? scopedDescriptors.find((field) => handles.get(field.handle) === target && isUsernameField(field))
    : undefined;
  const explicitUsername = scopedDescriptors.find((field) =>
    isUsernameField(field) && (field.autocomplete.includes("username") || field.autocomplete.includes("email") ||
    field.inputType === "email" || /user(name)?|login|account|e-?mail|用户名|账号|邮箱/i.test(fieldMetadata(field))),
  );
  const precedingUsername = scopedDescriptors.slice(0, firstPasswordIndex).reverse().find((field) =>
    field.control !== "select" && field.inputType !== "password" && [undefined, "", "text", "email", "tel"].includes(field.inputType),
  );
  const usernameField = targetUsername ?? explicitUsername ?? precedingUsername;
  if (!usernameField || passwordFields.length === 0) return { status: "no-login-fields" as const, results: [] };

  const currentOrigin = documentHttpOrigin(document);
  return applyAssignments({
    documentId: assignedDocumentId,
    currentDocumentId: () => resolveDocumentId(documentId),
    fields: handles,
    currentOrigin,
    message: {
      kind: "vaultmesh.apply-assignments",
      requestId: createUuid(),
      documentId: assignedDocumentId,
      frameOrigin: currentOrigin,
      expiresAt: new Date(Date.now() + 30_000).toISOString(),
      assignments: [
        { handle: usernameField.handle, value: login.username, overwrite: true },
        ...passwordFields.map((field) => ({ handle: field.handle, value: login.password, overwrite: true })),
      ],
    },
  });
}

export async function fillGeneratedPassword(document: Document, documentId: DocumentIdSource, target: HTMLInputElement, password: string) {
  const assignedDocumentId = resolveDocumentId(documentId);
  const { handles, descriptors } = discoverFields(document);
  const group = new Set(passwordFieldGroup(target));
  const passwordFields = descriptors.filter((field) => {
    if (field.control !== "input" || field.inputType !== "password") return false;
    const control = handles.get(field.handle);
    return control instanceof HTMLInputElement &&
      group.has(control) &&
      isNewPasswordControl(control);
  });
  if (passwordFields.length === 0) return { status: "no-new-password-fields" as const, results: [] };

  const currentOrigin = documentHttpOrigin(document);
  return applyAssignments({
    documentId: assignedDocumentId,
    currentDocumentId: () => resolveDocumentId(documentId),
    fields: handles,
    currentOrigin,
    message: {
      kind: "vaultmesh.apply-assignments",
      requestId: createUuid(),
      documentId: assignedDocumentId,
      frameOrigin: currentOrigin,
      expiresAt: new Date(Date.now() + 30_000).toISOString(),
      assignments: passwordFields.map((field) => ({ handle: field.handle, value: password, overwrite: true })),
    },
  });
}

function isUsernameField(field: { control: string; inputType?: string }) {
  return field.control !== "select" && field.inputType !== "password";
}

function fieldMetadata(field: { label: string; name: string; id: string; placeholder: string }) {
  return [field.label, field.name, field.id, field.placeholder].join(" ");
}

function resolveDocumentId(documentId: DocumentIdSource) {
  return typeof documentId === "function" ? documentId() : documentId;
}
