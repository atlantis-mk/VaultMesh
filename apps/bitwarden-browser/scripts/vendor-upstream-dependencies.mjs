// VaultMesh modification, 2026-09-10. One-time, explicit import; never run at build time.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const destination = fileURLToPath(new URL("../", import.meta.url));
const source = process.argv[2] && path.resolve(process.argv[2]);
if (!source || !fs.existsSync(path.join(source, "apps/browser/package.json"))) {
  throw new Error("Usage: node scripts/vendor-upstream-dependencies.mjs <clients-source-root>");
}
if (fs.existsSync(path.join(destination, "libs"))) {
  throw new Error("libs already exists; refusing to overwrite local changes.");
}
const json = (file) => JSON.parse(fs.readFileSync(path.join(source, file), "utf8"));
const upstream = json("package.json");
const lock = json("package-lock.json");
const config = json("tsconfig.base.json");
// Browser imports plus their shared-library closure; no other apps or commercial source.
const libraries = [
  "admin-console", "angular", "assets", "auth", "auto-confirm", "automation-driver",
  "client-type", "common", "components", "core-test-utils", "guid", "importer",
  "key-management", "key-management-ui", "legacy-crypto", "logging", "logging-angular",
  "managed-settings", "messaging", "organization-invite-link", "platform", "pricing",
  "scheduling", "serialization", "shared", "state", "state-internal", "state-test-utils",
  "storage-core", "storage-test-utils", "subscription", "tools", "ui", "unlock",
  "user-core", "user-crypto-management", "vault",
];
for (const library of libraries) {
  fs.cpSync(path.join(source, "libs", library), path.join(destination, "libs", library), {
    recursive: true, errorOnExist: true, force: false,
    filter: (file) => !file.split(path.sep).some((part) => ["node_modules", ".git", "dist"].includes(part)),
  });
}
for (const file of ["babel.config.json", ".browserslistrc"]) {
  fs.copyFileSync(path.join(source, file), path.join(destination, file), fs.constants.COPYFILE_EXCL);
}
config.compilerOptions.paths = Object.fromEntries(
  Object.entries(config.compilerOptions.paths).filter(([, targets]) =>
    targets.every((target) => libraries.some((lib) => target.startsWith(`./libs/${lib}/`)) &&
      [target.replace(/\*.*$/, ""), target + ".ts"].some((file) => fs.existsSync(path.join(source, file)))),
  ),
);
config.compilerOptions.paths["@bitwarden/browser/*"] = ["./src/*"];
config.compilerOptions.typeRoots = ["./node_modules/@types"];
const writeJson = (file, value) => fs.writeFileSync(path.join(destination, file), JSON.stringify(value, null, 2) + "\n");
writeJson("tsconfig.base.json", config);
const runtime = [
  "@angular/animations", "@angular/cdk", "@angular/common", "@angular/compiler", "@angular/core",
  "@angular/forms", "@angular/platform-browser", "@angular/router", "@bitwarden/sdk-internal",
  "@bufbuild/protobuf", "@emotion/css", "@lit-labs/signals", "@microsoft/signalr",
  "@microsoft/signalr-protocol-msgpack", "@ng-select/ng-select", "@webcomponents/custom-elements",
  "big-integer", "buffer", "core-js", "jszip", "lit", "lunr", "ngx-toastr", "node-forge",
  "oauth4webapi", "papaparse", "qrcode-parser", "rxjs", "semver", "tabbable", "tldts", "zone.js", "zod", "zxcvbn",
];
const development = [
  "@angular/compiler-cli", "@babel/core", "@babel/preset-env", "@ngtools/webpack",
  "@tailwindcss/container-queries", "@types/chrome", "@types/firefox-webext-browser", "@types/jest",
  "@types/lunr", "@types/node", "@types/node-forge", "@types/papaparse", "@types/semver", "@types/zxcvbn",
  "autoprefixer", "babel-loader", "copy-webpack-plugin", "cross-env", "css-loader", "html-loader",
  "html-webpack-plugin", "jest", "jest-diff", "jest-environment-jsdom", "jest-mock-extended",
  "jest-preset-angular", "jsdom", "mini-css-extract-plugin", "path-browserify", "postcss",
  "postcss-import", "postcss-loader", "postcss-nested", "pretty-format", "process", "resolve-url-loader",
  "sass", "sass-loader", "tailwindcss", "terser-webpack-plugin", "ts-jest", "ts-loader",
  "tsconfig-paths-webpack-plugin", "type-fest", "typescript", "typescript-strict-plugin", "url", "util",
  "webpack", "webpack-cli",
];
const versionOf = (name) => {
  const version = upstream.dependencies[name] ?? upstream.devDependencies[name] ?? lock.packages[`node_modules/${name}`]?.version;
  if (!version || /^(file:|workspace:)/.test(version)) throw new Error(`No registry version for ${name}`);
  return version;
};
const pkg = JSON.parse(fs.readFileSync(path.join(destination, "package.json"), "utf8"));
pkg.dependencies = Object.fromEntries(runtime.map((name) => [name, versionOf(name)]));
pkg.devDependencies = Object.fromEntries(development.map((name) => [name, versionOf(name)]));
// VaultMesh's existing branding generator uses sharp, independently of upstream tooling.
pkg.devDependencies.sharp = "0.35.4";
pkg.engines = upstream.engines;
// The separate lockfile is resolved for this subset, not the unrelated clients monorepo.
pkg.scripts = Object.fromEntries(Object.entries(pkg.scripts).filter(([key, value]) => !key.includes(":bit") && !value.includes("bitwarden_license")));
pkg.scripts["typecheck"] = "tsc --noEmit -p tsconfig.build.json";
pkg.scripts["dependencies:test"] = "node --test scripts/local-dependencies.test.mjs";
writeJson("package.json", pkg);
writeJson("upstream-dependencies.json", {
  browserVersion: json("apps/browser/package.json").version,
  importedOn: "2026-09-10",
  source: "User-supplied clients-main archive; no verified Git commit",
  libraries,
  sourceHashes: Object.fromEntries(["package.json", "package-lock.json", "tsconfig.base.json", "LICENSE.txt"].map((file) => [file, createHash("sha256").update(fs.readFileSync(path.join(source, file))).digest("hex")])),
  excluded: ["Other apps", "bitwarden_license", "commercial-sdk-internal", "desktop-napi", "Nx workspace", "Storybook toolchain"],
});
console.log(`Imported ${libraries.length} shared library directories and local build configuration.`);
