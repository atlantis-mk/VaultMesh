/**
 * Transform the manifest template into a browser specific manifest.
 *
 * We support a simple browser prefix to the manifest keys. Example:
 *
 * ```json
 * {
 *   "name": "Default name",
 *   "__chrome__name": "Chrome override"
 * }
 * ```
 *
 * Will result in the following manifest:
 *
 * ```json
 * {
 *  "name": "Chrome override"
 * }
 * ```
 *
 * for Chrome.
 */
function transform(browser) {
  return (buffer) => {
    let manifest = JSON.parse(buffer.toString());

    manifest = transformPrefixes(manifest, browser);
    manifest = transformChannel(manifest);
    // Only the adapted collector/qualification/executor lifecycle is reachable.
    manifest.content_scripts = [{
      all_frames: true, matches: ["http://*/*", "https://*/*"], run_at: "document_start",
      js: ["content/vaultmesh-native-fill.js"],
    }];
    manifest.permissions = ["storage", "tabs", "webNavigation", "idle"];
    manifest.optional_permissions = ["nativeMessaging"];
    if (["chrome", "edge"].includes(browser) && manifest.manifest_version === 3) {
      manifest.permissions.push("webAuthenticationProxy");
      manifest.minimum_chrome_version = "127";
    }
    if (manifest.manifest_version === 3) manifest.host_permissions = ["http://*/*", "https://*/*"];
    else manifest.permissions.push("http://*/*", "https://*/*");
    manifest.web_accessible_resources = manifest.manifest_version === 3
      ? [{ resources: ["images/*"], matches: ["http://*/*", "https://*/*"] }]
      : ["images/*"];
    delete manifest.side_panel;
    delete manifest.sidebar_action;
    delete manifest.externally_connectable;
    delete manifest.update_url;
    // Unsupported upstream commands must not appear as working integrations.
    manifest.commands = Object.fromEntries(Object.entries(manifest.commands ?? {}).filter(([key]) => key === "_execute_action" || key === "_execute_browser_action"));
    const identity = require("../development-identity.json");
    if (["chrome", "edge"].includes(browser)) manifest.key = identity.key;
    else delete manifest.key;
    if (browser === "firefox") {
      manifest.browser_specific_settings ??= {};
      manifest.browser_specific_settings.gecko ??= {};
      manifest.browser_specific_settings.gecko.id = identity.firefoxId;
      delete manifest.minimum_chrome_version;
      manifest.permissions = manifest.permissions?.filter((value) => value !== "webAuthenticationProxy");
    }

    return JSON.stringify(manifest, null, 2);
  };
}

// Beta channel manifest overrides live in `manifest-beta-overrides.json` so the diff
// between the stable and beta manifest is visible in one file. Nested
// overrides (e.g. action.default_title) are only merged when the target key
// already exists, which naturally handles the MV2 (`browser_action`) vs MV3
// (`action`) split. Version stamping is handled separately post-build by
// scripts/update-manifest-beta.sh.
function transformChannel(manifest) {
  if (process.env.CHANNEL !== "beta") {
    return manifest;
  }
  return applyOverrides(manifest, require("./manifest-beta-overrides.json"));
}

function applyOverrides(target, overrides) {
  for (const [key, value] of Object.entries(overrides)) {
    if (isPlainObject(value)) {
      if (target[key]) {
        applyOverrides(target[key], value);
      }
    } else {
      target[key] = value;
    }
  }
  return target;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const browsers = ["chrome", "edge", "firefox", "opera", "safari"];

/**
 * Flatten the browser prefixes in the manifest.
 *
 * - Removes unrelated browser prefixes.
 * - A null value deletes the non prefixed key.
 */
function transformPrefixes(manifest, browser) {
  const prefix = `__${browser}__`;

  function transformObject(obj) {
    return Object.keys(obj).reduce((acc, key) => {
      // Determine if we need to recurse into the object.
      const nested = typeof obj[key] === "object" && obj[key] !== null && !Array.isArray(obj[key]);

      if (key.startsWith(prefix)) {
        const newKey = key.slice(prefix.length);

        // Null values are used to remove keys.
        if (obj[key] == null) {
          delete acc[newKey];
          return acc;
        }

        acc[newKey] = nested ? transformObject(obj[key]) : obj[key];
      } else if (!browsers.some((b) => key.startsWith(`__${b}__`))) {
        acc[key] = nested ? transformObject(obj[key]) : obj[key];
      }

      return acc;
    }, {});
  }

  return transformObject(manifest);
}

module.exports = {
  transform,
};
