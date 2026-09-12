// CT-BROWSER-PACKAGE-001: experimental fork dependency isolation (not runtime acceptance).
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../", import.meta.url));
const require = createRequire(new URL("../package.json", import.meta.url));
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const json = (name) => JSON.parse(read(name));
const inside = (file) => {
  const relative = path.relative(root, file);
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};

test("all vendored aliases remain inside the fork and browser aliases resolve to src", () => {
  const { paths } = json("tsconfig.base.json").compilerOptions;
  assert.deepEqual(paths["@bitwarden/browser/*"], ["./src/*"]);
  for (const [alias, targets] of Object.entries(paths)) {
    assert(!/commercial|bit-common|web-vault|desktop|cli\//.test(alias), alias);
    for (const target of targets) {
      const file = path.resolve(root, target.replace(/\*.*$/, ""));
      assert(inside(file), target);
      assert(fs.existsSync(file) || fs.existsSync(file + ".ts"), target);
    }
  }
  for (const library of json("upstream-dependencies.json").libraries) {
    assert(fs.statSync(path.join(root, "libs", library)).isDirectory());
  }
});

test("build and test configuration does not reach into the parent monorepo", () => {
  for (const file of ["webpack.base.js", "tsconfig.json", "tsconfig.build.json", "jest.config.js", "tailwind.config.js"]) {
    assert(!/\.\.\/\.\.\/(?:libs|node_modules|babel\.config|tsconfig\.base|bitwarden_license)/.test(read(file)), file);
  }
  const ts = require("typescript");
  const parsed = ts.getParsedCommandLineOfConfigFile(path.join(root, "tsconfig.build.json"), {}, {
    ...ts.sys, onUnRecoverableConfigFileDiagnostic: (error) => assert.fail(ts.flattenDiagnosticMessageText(error.messageText, "\n")),
  });
  assert.deepEqual(parsed.errors, []);
  assert(parsed.fileNames.length > 0);
  assert(parsed.fileNames.every(inside));
  // Catch accidental success through packages/types installed in VaultMesh's parent tree.
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const escapedSources = program.getSourceFiles().map((file) => file.fileName).filter((file) => !inside(file));
  assert.deepEqual(escapedSources, []);
  const jest = require("./jest.config.js");
  for (const entry of jest.setupFiles) assert(inside(entry) && fs.existsSync(entry), entry);
  for (const value of Object.values(jest.moduleNameMapper).flat()) assert(!value.includes("<rootDir>/../../"));
});

test("Chrome background and popup compilers use the local runtime config and loaders", () => {
  const oldBrowser = process.env.BROWSER;
  const oldManifest = process.env.MANIFEST_VERSION;
  try {
    process.env.BROWSER = "chrome";
    process.env.MANIFEST_VERSION = "3";
    const configs = require("./webpack.config.js")();
    assert.equal(configs.length, 2);
    for (const config of configs) {
      assert.deepEqual(config.resolve.modules, [path.join(root, "node_modules")]);
      assert.deepEqual(config.resolveLoader.modules, [path.join(root, "node_modules")]);
      assert(inside(config.output.path));
      assert.equal(config.resolve.alias["@bitwarden/components/src"], path.join(root, "libs/components/src"));
      assert.equal(config.resolve.alias["@bitwarden/angular/src"], path.join(root, "libs/angular/src"));
      assert(fs.existsSync(path.join(config.resolve.alias["@bitwarden/components/src"], "webfonts/inter.woff2")));
      assert(fs.existsSync(path.join(config.resolve.alias["@bitwarden/angular/src"], "scss/bwicons/fonts/bwi-font.woff2")));
    }
    const background = configs.find((config) => config.name === "background");
    assert.equal(background.module.rules.find((rule) => rule.loader === "ts-loader").options.configFile, path.join(root, "tsconfig.build.json"));
  } finally {
    if (oldBrowser === undefined) delete process.env.BROWSER; else process.env.BROWSER = oldBrowser;
    if (oldManifest === undefined) delete process.env.MANIFEST_VERSION; else process.env.MANIFEST_VERSION = oldManifest;
  }
});

test("application stylesheet imports point to existing internal shared assets", () => {
  let checked = 0;
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(file);
      else if (/\.(scss|css)$/.test(file)) {
        for (const [, target] of fs.readFileSync(file, "utf8").matchAll(/@(?:import|use|forward)\s+["']([^"']*libs\/[^"']+)["']/g)) {
          const resolved = path.resolve(path.dirname(file), target);
          assert(inside(resolved), target);
          assert([resolved, resolved + ".scss", path.join(path.dirname(resolved), "_" + path.basename(resolved) + ".scss")].some(fs.existsSync), target);
          checked++;
        }
      }
    }
  };
  walk(path.join(root, "src"));
  assert(checked >= 8);
});

test("declared packages are locally installed and locked without other clients or commercial SDK", () => {
  const pkg = json("package.json");
  const lock = json("package-lock.json");
  assert.deepEqual(lock.packages[""].dependencies, pkg.dependencies);
  assert.deepEqual(lock.packages[""].devDependencies, pkg.devDependencies);
  for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
    assert(!/commercial|desktop-napi|electron/.test(name), name);
    assert(!/^(file:|workspace:)/.test(version), name);
    assert.equal(json(`node_modules/${name}/package.json`).version, version, name);
  }
  assert(!fs.existsSync(path.join(root, "bitwarden_license")));
  assert(!Object.values(pkg.scripts).some((script) => script.includes("bitwarden_license")));
  assert(fs.existsSync(path.join(root, "node_modules/@bitwarden/sdk-internal/bitwarden_wasm_internal_bg.wasm")));
});
