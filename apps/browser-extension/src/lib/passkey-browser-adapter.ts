export type PasskeyBrowserTarget = "chromium" | "firefox";

export type PasskeyBrowserEnv = {
  browser?: string;
  userAgent?: string;
};

export type PasskeyAdapterOperation = "create" | "get" | "availability";

export interface PasskeyBrowserAdapter {
  readonly target: PasskeyBrowserTarget;
  readonly isSupported: boolean;
  readonly disabledReason: string | null;
  allowsFrameWebAuthn(doc: Document, operation: PasskeyAdapterOperation): boolean;
  openPromptWindow(): Promise<void>;
}

type FeaturePolicyLike = {
  allowsFeature(feature: string): boolean;
};

type DocumentWithPolicies = Document & {
  permissionsPolicy?: FeaturePolicyLike;
  featurePolicy?: FeaturePolicyLike;
};

type ExtensionActionApi = {
  openPopup?: () => Promise<void>;
};

export class ChromiumPasskeyAdapter implements PasskeyBrowserAdapter {
  readonly target: PasskeyBrowserTarget = "chromium";
  readonly isSupported = true;
  readonly disabledReason: string | null = null;

  allowsFrameWebAuthn(doc: Document, operation: PasskeyAdapterOperation): boolean {
    const view = doc.defaultView;
    const isTopFrame = !view || view === view.top;
    const policy = (doc as DocumentWithPolicies).permissionsPolicy ?? (doc as DocumentWithPolicies).featurePolicy;
    if (!policy || typeof policy.allowsFeature !== "function") {
      return isTopFrame;
    }
    if (operation === "create") {
      return policy.allowsFeature("publickey-credentials-create") === true;
    }
    if (operation === "get") {
      return policy.allowsFeature("publickey-credentials-get") === true;
    }
    return (
      policy.allowsFeature("publickey-credentials-get") === true
      || policy.allowsFeature("publickey-credentials-create") === true
    );
  }

  async openPromptWindow(): Promise<void> {
    const browserApi = browser as unknown as {
      action?: ExtensionActionApi;
      browserAction?: ExtensionActionApi;
    };
    const action = browserApi.action ?? browserApi.browserAction;
    if (typeof action?.openPopup === "function") {
      try {
        await action.openPopup();
        return;
      } catch {
        // Fall through to a standalone unlock window when no focused browser window can host the popup.
      }
    }
    await browser.windows.create({
      url: browser.runtime.getURL("/popup.html?passkey=1"),
      type: "popup",
      focused: true,
      width: 400,
      height: 600,
    });
  }
}

export class FirefoxPasskeyAdapter implements PasskeyBrowserAdapter {
  readonly target: PasskeyBrowserTarget = "firefox";
  readonly isSupported = false;
  readonly disabledReason = "firefox-unsupported";

  allowsFrameWebAuthn(): boolean {
    return false;
  }

  async openPromptWindow(): Promise<void> {
    // Firefox Passkey proxying is disabled because it lacks conditional mediation and Permissions Policy APIs.
  }
}

const CHROMIUM_ADAPTER = new ChromiumPasskeyAdapter();
const FIREFOX_ADAPTER = new FirefoxPasskeyAdapter();

function isFirefoxUserAgent(ua: string): boolean {
  return /Firefox\//i.test(ua) && !/Seamonkey|Chrom(e|ium)|Edg/i.test(ua);
}

export const PasskeyBrowserFactory = {
  currentTarget(env?: PasskeyBrowserEnv): PasskeyBrowserTarget {
    if (typeof env?.browser === "string") {
      if (env.browser.toLocaleLowerCase() === "firefox") return "firefox";
      if (env.browser.length > 0) return "chromium";
    }
    if (typeof env?.userAgent === "string") {
      return isFirefoxUserAgent(env.userAgent) ? "firefox" : "chromium";
    }
    const runtimeBrowser = import.meta.env.BROWSER;
    if (typeof runtimeBrowser === "string" && runtimeBrowser.length > 0) {
      return runtimeBrowser.toLocaleLowerCase() === "firefox" ? "firefox" : "chromium";
    }
    const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
    return isFirefoxUserAgent(ua) ? "firefox" : "chromium";
  },

  createFor(target: PasskeyBrowserTarget): PasskeyBrowserAdapter {
    return target === "firefox" ? FIREFOX_ADAPTER : CHROMIUM_ADAPTER;
  },

  create(env?: PasskeyBrowserEnv): PasskeyBrowserAdapter {
    return this.createFor(this.currentTarget(env));
  },
};
