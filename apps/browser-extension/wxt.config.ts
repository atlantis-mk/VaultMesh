import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "wxt";

export default defineConfig({
  srcDir: "src",
  modules: ["@wxt-dev/module-react"],
  ...(process.env.VAULTMESH_BROWSER_PROFILE
    ? {
        webExt: {
          chromiumProfile: process.env.VAULTMESH_BROWSER_PROFILE,
          keepProfileChanges: true,
        },
      }
    : {}),
  manifest: ({ browser }) => {
    const isFirefox = browser === "firefox";
    return {
    name: "VaultMesh",
    description: "Use VaultMesh securely from the browser popup.",
    ...(isFirefox ? {} : { minimum_chrome_version: "127" }),
    ...(isFirefox
      ? {
          browser_specific_settings: {
            gecko: {
              id: process.env.VAULTMESH_FIREFOX_EXTENSION_ID ?? "vaultmesh@atlantis-mk.github.io",
              strict_min_version: "128.0",
              data_collection_permissions: {
                required: ["none"],
              },
            },
          },
        }
      : {}),
    icons: {
      "16": "icon-16.png",
      "32": "icon-32.png",
      "48": "icon-48.png",
      "128": "icon-128.png",
    },
    action: {
      default_icon: {
        "16": "icon-16.png",
        "32": "icon-32.png",
      },
    },
    permissions: [
      "alarms", "clipboardRead", "contextMenus", "idle",
      "nativeMessaging", "notifications", "storage", "webNavigation",
      ...(!isFirefox ? ["webAuthenticationProxy" as const] : []),
    ],
    host_permissions: ["http://*/*", "https://*/*"],
    commands: {
      "request-identity-fill": {
        description: "Fill this form with a selected VaultMesh item"
      }
    },
    ...(!isFirefox && process.env.WXT_CHROME_EXTENSION_KEY
      ? { key: process.env.WXT_CHROME_EXTENSION_KEY }
      : {})
    };
  },
  vite: () => ({
    plugins: [tailwindcss()]
  })
});
