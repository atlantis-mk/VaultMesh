import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workspace = new URL("../", import.meta.url);

async function source(relativePath) {
  return readFile(new URL(relativePath, workspace), "utf8");
}

function stdUseBlocks(text) {
  const blocks = [];
  const pattern = /(?:#\[cfg\(([^)]+)\)\]\s*)?use\s+std::\{/g;
  for (const match of text.matchAll(pattern)) {
    const open = match.index + match[0].length - 1;
    let depth = 0;
    let end = open;
    for (; end < text.length; end += 1) {
      if (text[end] === "{") depth += 1;
      else if (text[end] === "}") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    blocks.push({
      cfg: match[1] ?? null,
      body: text.slice(open + 1, end),
    });
  }
  return blocks;
}

test("shared broker imports stay available to the ungated HTTP listener", async () => {
  const part1 = await source("apps/tauri-desktop/src-tauri/src/browser_broker_part1.inc.rs");
  const blocks = stdUseBlocks(part1);
  const ungated = blocks.filter((block) => block.cfg === null).map((block) => block.body).join("\n");
  const unix = blocks.filter((block) => block.cfg === "unix").map((block) => block.body).join("\n");

  for (const name of ["Read", "Write", "AtomicBool", "Ordering", "thread", "JoinHandle", "Duration"]) {
    assert.match(ungated, new RegExp(`\\b${name}\\b`), `${name} must be imported outside #[cfg(unix)]`);
  }
  assert.match(unix, /\bUnixListener\b/);
  assert.match(unix, /\bFileTypeExt\b/);
  assert.doesNotMatch(ungated, /\bUnixListener\b/);
  assert.doesNotMatch(ungated, /\bos::unix\b/);

  const broker = await source("apps/tauri-desktop/src-tauri/src/browser_broker.rs");
  assert.match(broker, /^include!\("browser_broker_http\.inc\.rs"\);$/m);
  assert.doesNotMatch(broker, /#\[cfg[^\n]*\ninclude!\("browser_broker_http\.inc\.rs"\)/);

  const part2 = await source("apps/tauri-desktop/src-tauri/src/browser_broker_part2.inc.rs");
  const beforeUnixCfg = part2.split("#[cfg(unix)]", 1)[0];
  assert.match(beforeUnixCfg, /Ordering::AcqRel/);

  const http = await source("apps/tauri-desktop/src-tauri/src/browser_broker_http.inc.rs");
  assert.match(http, /AtomicBool/);
  assert.match(http, /JoinHandle/);
  assert.match(http, /thread::/);
  assert.match(http, /Ordering::/);
  assert.match(http, /Duration::/);
  assert.match(http, /write_all/);
  assert.match(http, /\.read\(/);
  assert.match(http, /\.flush\(/);
});
