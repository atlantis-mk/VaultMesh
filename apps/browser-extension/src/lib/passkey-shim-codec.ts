/** Pure WebAuthn JSON codec used by the MAIN-world shim. It carries no secrets:
 * it only converts page-supplied options to the JSON form the desktop validates
 * and turns the desktop's public response back into browser credential objects. */

export type JsonObject = Record<string, unknown>;

export const MAX_PASSKEY_JSON_CHARS = 128 * 1024;
export const MAX_PASSKEY_RESPONSE_CHARS = 256 * 1024;

/** Extensions the desktop honours. */
const SUPPORTED_EXTENSIONS = new Set(['appid', 'credProps']);
/** Extensions whose result the page depends on. Ignoring them would hand the
 * page a credential it cannot use, so the browser must serve those requests.
 * Every other extension is advisory and is dropped, as the former proxy did. */
const RESULT_BEARING_EXTENSIONS = new Set(['prf', 'largeBlob', 'hmacCreateSecret', 'credBlob', 'getCredBlob', 'payment']);

/** Name of the first extension that forces a browser fallback, if any. */
export function blockingExtension(extensions: AuthenticationExtensionsClientInputs | undefined): string | null {
  if (!extensions) return null;
  for (const [name, value] of Object.entries(extensions as Record<string, unknown>)) {
    if (value === undefined) continue;
    if (RESULT_BEARING_EXTENSIONS.has(name)) return name;
    if (name === 'enforceCredentialProtectionPolicy' && value === true) return name;
    if (name === 'appid' && typeof value !== 'string') return name;
    if (name === 'credProps' && typeof value !== 'boolean') return name;
  }
  return null;
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

export function toBase64Url(data: BufferSource): string {
  // `instanceof ArrayBuffer` is false for buffers made in another realm (iframe, worker),
  // which would silently encode as empty. Views are detected structurally instead.
  const bytes = ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data as ArrayBuffer);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: unknown): ArrayBuffer {
  if (typeof value !== 'string' || !BASE64URL.test(value) || value.length % 4 === 1) throw new TypeError('Invalid base64url');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}

function encodeDescriptors(descriptors: PublicKeyCredentialDescriptor[] | undefined): JsonObject[] {
  return (descriptors ?? []).map((descriptor) => ({
    type: descriptor.type,
    id: toBase64Url(descriptor.id),
    ...(descriptor.transports ? { transports: [...descriptor.transports] } : {}),
  }));
}

/** Returns `null` when the page asks for a result-bearing extension this build cannot serve. */
function encodeExtensions(extensions: AuthenticationExtensionsClientInputs | undefined): JsonObject | null {
  if (blockingExtension(extensions)) return null;
  const encoded: JsonObject = {};
  if (!extensions) return encoded;
  for (const [name, value] of Object.entries(extensions as Record<string, unknown>)) {
    if (value !== undefined && SUPPORTED_EXTENSIONS.has(name)) encoded[name] = value;
  }
  return encoded;
}

export function encodeCreationOptions(options: PublicKeyCredentialCreationOptions): JsonObject | null {
  const extensions = encodeExtensions(options.extensions);
  if (!extensions) return null;
  const selection = options.authenticatorSelection;
  return {
    rp: { ...(options.rp.id === undefined ? {} : { id: options.rp.id }), name: options.rp.name },
    user: { id: toBase64Url(options.user.id), name: options.user.name, displayName: options.user.displayName },
    challenge: toBase64Url(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams.map((parameter) => ({ type: parameter.type, alg: parameter.alg })),
    excludeCredentials: encodeDescriptors(options.excludeCredentials),
    ...(selection ? {
      authenticatorSelection: {
        ...(selection.authenticatorAttachment ? { authenticatorAttachment: selection.authenticatorAttachment } : {}),
        ...(selection.residentKey ? { residentKey: selection.residentKey } : {}),
        ...(selection.userVerification ? { userVerification: selection.userVerification } : {}),
      },
    } : {}),
    extensions,
  };
}

export function encodeRequestOptions(options: PublicKeyCredentialRequestOptions): JsonObject | null {
  const extensions = encodeExtensions(options.extensions);
  if (!extensions) return null;
  return {
    challenge: toBase64Url(options.challenge),
    ...(options.rpId === undefined ? {} : { rpId: options.rpId }),
    allowCredentials: encodeDescriptors(options.allowCredentials),
    ...(options.userVerification ? { userVerification: options.userVerification } : {}),
    extensions,
  };
}

export type CredentialConstructors = {
  PublicKeyCredential: { prototype: object };
  AuthenticatorAttestationResponse: { prototype: object };
  AuthenticatorAssertionResponse: { prototype: object };
};

/** Data attributes (`id`, `rawId`, `response`, ...) are read-only, like the real accessors without a setter. */
function defineReadonly(target: object, properties: Record<string, unknown>) {
  for (const [name, value] of Object.entries(properties)) {
    Object.defineProperty(target, name, { value, enumerable: true, configurable: true, writable: false });
  }
}

/** Operations (`toJSON`, `getTransports`, ...) must stay assignable: real ones live on the prototype,
 * and libraries such as @github/webauthn-json do `credential.toJSON = ...` in strict mode. */
function defineMethods(target: object, methods: Record<string, unknown>) {
  for (const [name, value] of Object.entries(methods)) {
    Object.defineProperty(target, name, { value, enumerable: true, configurable: true, writable: true });
  }
}

function object(value: unknown): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Invalid Passkey response');
  return value as JsonObject;
}

function text(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError('Invalid Passkey response');
  return value;
}

function buildCredential(
  json: JsonObject,
  response: object,
  constructors: CredentialConstructors,
): PublicKeyCredential {
  if (json.type !== 'public-key') throw new TypeError('Invalid Passkey response');
  const extensionResults = json.clientExtensionResults === undefined ? {} : object(json.clientExtensionResults);
  const credential = Object.create(constructors.PublicKeyCredential.prototype) as object;
  defineReadonly(credential, {
    id: text(json.id),
    rawId: fromBase64Url(json.rawId),
    type: 'public-key',
    authenticatorAttachment: typeof json.authenticatorAttachment === 'string' ? json.authenticatorAttachment : null,
    response,
  });
  defineMethods(credential, {
    getClientExtensionResults: () => ({ ...extensionResults }),
    toJSON: () => JSON.parse(JSON.stringify(json)) as unknown,
  });
  return credential as PublicKeyCredential;
}

export function credentialFromCreateJson(value: unknown, constructors: CredentialConstructors): PublicKeyCredential {
  const json = object(value);
  const raw = object(json.response);
  const publicKey = raw.publicKey === undefined || raw.publicKey === null ? null : fromBase64Url(raw.publicKey);
  const transports = Array.isArray(raw.transports) ? raw.transports.filter((entry): entry is string => typeof entry === 'string') : [];
  const response = Object.create(constructors.AuthenticatorAttestationResponse.prototype) as object;
  const authenticatorData = fromBase64Url(raw.authenticatorData);
  defineReadonly(response, {
    clientDataJSON: fromBase64Url(raw.clientDataJSON),
    attestationObject: fromBase64Url(raw.attestationObject),
  });
  defineMethods(response, {
    getTransports: () => [...transports],
    getAuthenticatorData: () => authenticatorData.slice(0),
    getPublicKey: () => (publicKey ? publicKey.slice(0) : null),
    getPublicKeyAlgorithm: () => (typeof raw.publicKeyAlgorithm === 'number' ? raw.publicKeyAlgorithm : -7),
  });
  return buildCredential(json, response, constructors);
}

export function credentialFromGetJson(value: unknown, constructors: CredentialConstructors): PublicKeyCredential {
  const json = object(value);
  const raw = object(json.response);
  const response = Object.create(constructors.AuthenticatorAssertionResponse.prototype) as object;
  defineReadonly(response, {
    clientDataJSON: fromBase64Url(raw.clientDataJSON),
    authenticatorData: fromBase64Url(raw.authenticatorData),
    signature: fromBase64Url(raw.signature),
    userHandle: typeof raw.userHandle === 'string' && raw.userHandle.length > 0 ? fromBase64Url(raw.userHandle) : null,
  });
  return buildCredential(json, response, constructors);
}
