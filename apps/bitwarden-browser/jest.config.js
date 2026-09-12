const { pathsToModuleNameMapper } = require("ts-jest");

const { compilerOptions } = require("./tsconfig.base.json");

const sharedConfig = require("./libs/shared/jest.config.angular");

/** @type {import('jest').Config} */
module.exports = {
  ...sharedConfig,
  testMatch: ["<rootDir>/src/**/*.spec.ts"],
  // Compile the real ESM Lit directives used by the bundled VaultMesh SVG.
  transformIgnorePatterns: [
    "node_modules/(?!(.*\\.mjs$|@angular/common/locales/.*\\.js$|oauth4webapi/.*|lit/|lit-html/|lit-element/|@lit/))",
  ],
  setupFilesAfterEnv: ["<rootDir>/test.setup.ts"],
  moduleNameMapper: pathsToModuleNameMapper(
    { "@bitwarden/common/spec": ["libs/common/spec"], ...(compilerOptions?.paths ?? {}) },
    {
      prefix: "<rootDir>/",
    },
  ),
};
