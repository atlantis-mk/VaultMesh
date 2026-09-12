// Refresh only the two intentional inline-logo snapshots, retaining their
// existing test names and button attributes. Does not update behavioral tests.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import { format, plugins } from "pretty-format";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const icons = readFileSync(resolve(root, "src/branding/vaultmesh-icons.ts"), "utf8");
const path = resolve(root, "src/autofill/overlay/inline-menu/pages/button/__snapshots__/autofill-inline-menu-button.spec.ts.snap");
const old = readFileSync(path, "utf8");
const dom = new JSDOM();
const document = dom.window.document;
const result = old.replace(/exports\[`([^`]+)`\] = `\n[\s\S]*?\n`;/g, (_, name) => {
  const isLocked = name.includes("locked icon");
  const symbol = isLocked ? "vaultMeshLockedIcon" : "vaultMeshIcon";
  const match = icons.match(new RegExp(`export const ${symbol} = (.*);`));
  if (!match) throw new Error(`Missing ${symbol}`);
  const svg = new dom.window.DOMParser().parseFromString(JSON.parse(match[1]), "image/svg+xml").documentElement;
  if (svg.localName !== "svg") throw new Error("Invalid generated SVG");
  svg.setAttribute("aria-hidden", "true");
  svg.classList.add("inline-menu-button-svg-icon", isLocked ? "logo-locked-icon" : "logo-icon");
  const button = document.createElement("button");
  button.setAttribute("aria-label", "toggleBitwardenVaultOverlay");
  button.classList.add("inline-menu-button"); button.tabIndex = -1; button.type = "button";
  button.append(svg);
  return `exports[\`${name}\`] = \`\n${format(button, { plugins: [plugins.DOMElement, plugins.DOMCollection], escapeRegex: true, printFunctionName: false })}\n\`;`;
});
writeFileSync(path, result); dom.window.close();
console.log("Updated the two inline branding snapshots.");
