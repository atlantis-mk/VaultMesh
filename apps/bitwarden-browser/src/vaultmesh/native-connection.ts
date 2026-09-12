// VaultMesh native host identity is fixed by the desktop/browser contract.
// Do not inherit Bitwarden's `com.8bit.bitwarden` host or an environment value.
const NATIVE_HOST_NAME = "com.vaultmesh.bitwarden.dev";
const REQUEST_TIMEOUT_MS = 70_000;
const MAX_RECONNECT_DELAY_MS = 30_000;
const STABLE_CONNECTION_MS = 30_000;
const RESTART_NATIVE_HOST_STATUSES = new Set(["desktop-unavailable", "invalid-broker-response", "unpaired"]);

type NativePort = ReturnType<typeof chrome.runtime.connectNative>;
type PendingRequest = {
  resolve: (response: unknown) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
};

export type NativeRpcRequest = {
  kind: "vaultmesh.rpc";
  version: 2;
  requestId: string;
  issuedAt: string;
  expiresAt: string;
  operation: string;
  input: Record<string, unknown>;
};

/**
 * Owns one native-messaging port for the lifetime of the extension background
 * worker. RPC responses are correlated because a long-lived port can carry
 * multiple requests at the same time.
 */
export class PersistentNativeConnection {
  #port: NativePort | null = null;
  #pending = new Map<string, PendingRequest>();
  #reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  #stableTimer: ReturnType<typeof setTimeout> | null = null;
  #reconnectAttempt = 0;
  #running = false;
  #disconnectListeners = new Set<() => void>();

  constructor(
    private readonly connect: () => NativePort = () => chrome.runtime.connectNative(NATIVE_HOST_NAME),
    private readonly requestTimeoutMs = REQUEST_TIMEOUT_MS,
  ) {}

  start(): void {
    this.#running = true;
    this.#ensurePort();
  }

  request(message: NativeRpcRequest): Promise<unknown> {
    this.start();
    return new Promise((resolve, reject) => {
      const port = this.#port;
      const timeout = setTimeout(() => {
        this.#settle(message.requestId, undefined, new Error("desktop-unavailable"));
        if (port) this.#restartPort(port);
      }, this.requestTimeoutMs);
      this.#pending.set(message.requestId, { resolve, reject, timeout });

      if (!port) {
        this.#settle(message.requestId, undefined, new Error("desktop-unavailable"));
        return;
      }

      try {
        port.postMessage(message);
      } catch {
        this.#settle(message.requestId, undefined, new Error("desktop-unavailable"));
        this.#restartPort(port);
      }
    });
  }

  /** Used by the background alarm to recover if MV3 suspended a retry timer. */
  ensureConnected(): void {
    if (!this.#running) this.#running = true;
    this.#ensurePort();
  }

  onDisconnected(listener: () => void): () => void {
    this.#disconnectListeners.add(listener);
    return () => this.#disconnectListeners.delete(listener);
  }

  dispose(): void {
    this.#running = false;
    if (this.#reconnectTimer) clearTimeout(this.#reconnectTimer);
    if (this.#stableTimer) clearTimeout(this.#stableTimer);
    this.#reconnectTimer = null;
    this.#stableTimer = null;
    const port = this.#port;
    this.#port = null;
    port?.disconnect();
    for (const requestId of [...this.#pending.keys()]) {
      this.#settle(requestId, undefined, new Error("desktop-unavailable"));
    }
  }

  #ensurePort(): void {
    if (!this.#running || this.#port) return;
    try {
      const port = this.connect();
      this.#port = port;
      port.onMessage.addListener((response) => this.#handleMessage(port, response));
      port.onDisconnect.addListener(() => {
        // Consume the browser error without logging native-host details.
        void chrome.runtime.lastError;
        this.#handleDisconnect(port);
      });
      this.#stableTimer = setTimeout(() => {
        if (port === this.#port) this.#reconnectAttempt = 0;
        this.#stableTimer = null;
      }, STABLE_CONNECTION_MS);
    } catch {
      this.#scheduleReconnect();
    }
  }

  #handleMessage(port: NativePort, response: unknown): void {
    if (port !== this.#port) return;
    const shouldRestartHost = shouldRestartNativeHost(response);
    if (!shouldRestartHost) {
      this.#reconnectAttempt = 0;
      if (this.#stableTimer) clearTimeout(this.#stableTimer);
      this.#stableTimer = null;
    }
    const requestId = responseRequestId(response);
    if (requestId) {
      this.#settle(requestId, response);
      if (shouldRestartHost) this.#restartPort(port);
      return;
    }

    // Older hosts returned uncorrelated host-level failures. Such a failure
    // applies to every in-flight request and remains safe during upgrades.
    if (isHostStatus(response)) {
      for (const pendingId of [...this.#pending.keys()]) this.#settle(pendingId, response);
      if (shouldRestartHost) this.#restartPort(port);
    }
  }

  #restartPort(port: NativePort): void {
    if (port !== this.#port) return;
    this.#handleDisconnect(port);
    try {
      port.disconnect();
    } catch {
      // Chromium may already have closed the native port.
    }
  }

  #handleDisconnect(port: NativePort | null): void {
    if (port !== this.#port) return;
    if (this.#stableTimer) clearTimeout(this.#stableTimer);
    this.#stableTimer = null;
    this.#port = null;
    for (const listener of this.#disconnectListeners) listener();
    for (const requestId of [...this.#pending.keys()]) {
      this.#settle(requestId, undefined, new Error("desktop-unavailable"));
    }
    this.#scheduleReconnect();
  }

  #scheduleReconnect(): void {
    if (!this.#running || this.#reconnectTimer) return;
    const delay = Math.min(1_000 * 2 ** this.#reconnectAttempt, MAX_RECONNECT_DELAY_MS);
    this.#reconnectAttempt += 1;
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = null;
      this.#ensurePort();
    }, delay);
  }

  #settle(requestId: string, response?: unknown, error?: Error): void {
    const pending = this.#pending.get(requestId);
    if (!pending) return;
    this.#pending.delete(requestId);
    clearTimeout(pending.timeout);
    if (error) pending.reject(error);
    else pending.resolve(response);
  }
}

export const persistentNativeConnection = new PersistentNativeConnection();

function responseRequestId(response: unknown): string | null {
  if (!response || typeof response !== "object") return null;
  const requestId = (response as { requestId?: unknown }).requestId;
  return typeof requestId === "string" ? requestId : null;
}

function isHostStatus(response: unknown): boolean {
  return Boolean(response && typeof response === "object" && (response as { kind?: unknown }).kind === "vaultmesh.host-status");
}

function shouldRestartNativeHost(response: unknown): boolean {
  if (!isHostStatus(response)) return false;
  const status = (response as { status?: unknown }).status;
  return typeof status === "string" && RESTART_NATIVE_HOST_STATUSES.has(status);
}
