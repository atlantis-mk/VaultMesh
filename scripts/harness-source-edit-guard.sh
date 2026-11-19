#!/bin/bash
set -euo pipefail

# AGY Harness Software 1.0 PreToolUse Parent Source-Edit Guard.
# Blocks the top-level coordinator session (transcript starts with USER_INPUT /
# USER_EXPLICIT) from directly modifying project source/test files when:
#   1) an active contract exists in .artifacts/SPEC.md or .artifacts/PLAN.md, OR
#   2) current changes exceed the Tier S fast-lane threshold (<= 3 non-harness
#      files and <= 150 net changed lines).
# Subagents (transcript starts with SYSTEM_MESSAGE) and edits under .artifacts/,
# .agents/, or outside the repository root are allowed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOK_STDIN="$(cat || true)"
[ -z "$HOOK_STDIN" ] && HOOK_STDIN="{}"

export AGY_GUARD_REPO_ROOT="$REPO_ROOT"
export AGY_GUARD_STDIN="$HOOK_STDIN"

if command -v node >/dev/null 2>&1; then
  exec node -e '
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const emit = (decision, reason) => {
  process.stdout.write(JSON.stringify(reason ? { decision, reason } : { decision }) + "\n");
  process.exit(0);
};

let input = {};
try {
  input = JSON.parse(process.env.AGY_GUARD_STDIN || "{}");
} catch {
  emit("allow");
}

const tc = input.toolCall || {};
const toolName = String(tc.name || "");
const args = tc.args || {};

const EDIT_TOOLS = new Set([
  "edit_file",
  "write_file",
  "write_to_file",
  "replace_file_content",
  "multi_replace_file_content",
]);
if (!EDIT_TOOLS.has(toolName)) {
  emit("allow");
}

const rawTarget = String(args.Path || args.TargetFile || args.path || args.file || "")
  .replace(/^"+|"+$/g, "")
  .trim();
if (!rawTarget) {
  emit("allow");
}

const resolveReal = (targetPath, baseDir) => {
  const parts = [];
  let cur = path.resolve(baseDir, targetPath);
  while (!fs.existsSync(cur)) {
    const parent = path.dirname(cur);
    if (parent === cur) break;
    parts.unshift(path.basename(cur));
    cur = parent;
  }
  let realBase = cur;
  try {
    realBase = fs.realpathSync(cur);
  } catch {}
  return parts.length ? path.join(realBase, ...parts) : realBase;
};

const rawRepo =
  (Array.isArray(input.workspacePaths) && input.workspacePaths[0] && fs.existsSync(input.workspacePaths[0]))
    ? input.workspacePaths[0]
    : (process.env.AGY_GUARD_REPO_ROOT || process.cwd());
const repoRoot = resolveReal(rawRepo, process.cwd());
const absTarget = resolveReal(rawTarget, repoRoot);

if (!absTarget.startsWith(repoRoot + path.sep)) {
  emit("allow");
}

const rel = path.relative(repoRoot, absTarget).replace(/\\/g, "/");
const isHarnessInternal = (relPath) =>
  relPath === ".artifacts" ||
  relPath.startsWith(".artifacts/") ||
  relPath === ".agents" ||
  relPath.startsWith(".agents/");

if (isHarnessInternal(rel)) {
  emit("allow");
}

let isParent = false;
const tp = input.transcriptPath ? String(input.transcriptPath) : "";
if (tp && fs.existsSync(tp)) {
  try {
    const firstLine = fs
      .readFileSync(tp, "utf8")
      .split(/\r?\n/)
      .find((line) => line.trim().length > 0);
    if (firstLine) {
      const firstObj = JSON.parse(firstLine);
      if (firstObj && (firstObj.type === "USER_INPUT" || firstObj.source === "USER_EXPLICIT")) {
        isParent = true;
      }
    }
  } catch {
    emit("allow");
  }
}
if (!isParent) {
  emit("allow");
}

const specPath = path.join(repoRoot, ".artifacts", "SPEC.md");
const planPath = path.join(repoRoot, ".artifacts", "PLAN.md");
const isSpecActive = (() => {
  if (!fs.existsSync(specPath)) return false;
  const txt = fs.readFileSync(specPath, "utf8");
  return (
    txt.trim().length > 0 &&
    !txt.includes("_Describe the concrete user or system problem being solved._") &&
    !txt.includes("<!-- HARNESS_TEMPLATE_UNFILLED")
  );
})();
const isPlanActive = (() => {
  if (!fs.existsSync(planPath)) return false;
  const txt = fs.readFileSync(planPath, "utf8");
  return (
    txt.trim().length > 0 &&
    !txt.includes("## Slice 1: [Title]") &&
    !txt.includes("<!-- HARNESS_TEMPLATE_UNFILLED")
  );
})();

if (isSpecActive || isPlanActive) {
  emit(
    "deny",
    "BLOCKED by AGY Harness Source-Edit Guard: Active contract found in .artifacts/SPEC.md or .artifacts/PLAN.md. Top-level coordinator MUST NOT directly edit `" +
      rel +
      "`. Wait for user Proceed and delegate ALL implementation/rework edits to `slice-builder` via `invoke_subagent` or `send_message`."
  );
}

// No active contract: evaluate Tier S fast-lane threshold (<= 3 files and <= 150 changed lines).
const runGit = (gitArgs) => {
  try {
    return execFileSync("git", ["--no-pager", ...gitArgs], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2500,
    });
  } catch {
    return null;
  }
};

const inGit = runGit(["rev-parse", "--is-inside-work-tree"]);
if (!inGit || inGit.trim() !== "true") {
  emit("allow");
}

const HARNESS_BOOTSTRAP_PATHS = new Set([
  ".gitignore",
  "scripts/gate-check.sh",
  "scripts/harness-approval-gate.sh",
  "scripts/harness-source-edit-guard.sh",
]);
const skipBackgroundBudgetCount = (relPath) =>
  isHarnessInternal(relPath) || (relPath !== rel && HARNESS_BOOTSTRAP_PATHS.has(relPath));

const statusOut = runGit(["status", "--porcelain=v1", "-uall"]) || "";
const touchedFiles = new Set([rel]);
const untrackedFiles = [];
for (const rawLine of statusOut.split(/\r?\n/)) {
  if (!rawLine || rawLine.length < 4) continue;
  const code = rawLine.slice(0, 2);
  let p = rawLine.slice(3).trim();
  const arrowIdx = p.indexOf(" -> ");
  if (arrowIdx >= 0) p = p.slice(arrowIdx + 4);
  p = p.replace(/^"+|"+$/g, "").replace(/\\/g, "/");
  if (!p || skipBackgroundBudgetCount(p)) continue;
  touchedFiles.add(p);
  if (code === "??") untrackedFiles.push(p);
}

if (touchedFiles.size > 3) {
  emit(
    "deny",
    "BLOCKED by AGY Harness Source-Edit Guard: Exceeds Tier S file budget (" +
      touchedFiles.size +
      " > 3 non-harness files, target `" +
      rel +
      "`). Escalate to Tier M/L: draft .artifacts/{SPEC,PLAN}.md + <ArtifactDir>/harness_plan.md (RequestFeedback=true), wait for Proceed, and delegate implementation to `slice-builder`."
  );
}

const hasHead = runGit(["rev-parse", "--verify", "HEAD"]) !== null;
const numstatArgs = hasHead ? ["diff", "--numstat", "HEAD"] : ["diff", "--numstat", "--cached"];
const numstatOut = runGit(numstatArgs) || "";
let changedLines = 0;

for (const line of numstatOut.split(/\r?\n/)) {
  if (!line.trim()) continue;
  const parts = line.split("\t");
  if (parts.length < 3) continue;
  const p = parts[parts.length - 1].replace(/^"+|"+$/g, "").replace(/\\/g, "/");
  if (skipBackgroundBudgetCount(p)) continue;
  const add = Number.parseInt(parts[0], 10);
  const del = Number.parseInt(parts[1], 10);
  if (Number.isFinite(add)) changedLines += add;
  if (Number.isFinite(del)) changedLines += del;
}

for (const uFile of untrackedFiles) {
  const full = resolveReal(uFile, repoRoot);
  if (!full.startsWith(repoRoot + path.sep) || !fs.existsSync(full)) continue;
  try {
    const stat = fs.statSync(full);
    if (!stat.isFile()) continue;
    const raw = fs.readFileSync(full);
    if (raw.includes(0)) continue;
    const text = raw.toString("utf8");
    changedLines += text ? text.split(/\r?\n/).length : 0;
  } catch {}
}

let pendingAddedLines = 0;
if ((toolName === "write_file" || toolName === "write_to_file") && typeof args.Content === "string" && !fs.existsSync(absTarget)) {
  pendingAddedLines = args.Content ? args.Content.split(/\r?\n/).length : 0;
} else if (typeof args.Replacement === "string") {
  const repLines = args.Replacement ? args.Replacement.split(/\r?\n/).length : 0;
  const tgtLines = typeof args.Target === "string" && args.Target ? args.Target.split(/\r?\n/).length : 0;
  pendingAddedLines = Math.max(0, repLines - tgtLines);
}

const projectedLines = changedLines + pendingAddedLines;
if (projectedLines > 150) {
  emit(
    "deny",
    "BLOCKED by AGY Harness Source-Edit Guard: Exceeds Tier S line budget (" +
      projectedLines +
      " > 150 changed lines including `" +
      rel +
      "`). Escalate to Tier M/L: draft .artifacts/{SPEC,PLAN}.md + <ArtifactDir>/harness_plan.md (RequestFeedback=true), wait for Proceed, and delegate implementation to `slice-builder`."
  );
}

emit("allow");
'
fi

if command -v python3 >/dev/null 2>&1; then
  exec python3 - <<'PY'
import json, os, pathlib, subprocess, sys

def emit(decision, reason=None):
    out = {"decision": decision}
    if reason:
        out["reason"] = reason
    sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
    sys.exit(0)

try:
    data = json.loads(os.environ.get("AGY_GUARD_STDIN") or "{}")
except Exception:
    emit("allow")

tc = data.get("toolCall") or {}
tool_name = str(tc.get("name") or "")
args = tc.get("args") or {}

if tool_name not in {"edit_file", "write_file", "write_to_file", "replace_file_content", "multi_replace_file_content"}:
    emit("allow")

raw_target = str(args.get("Path") or args.get("TargetFile") or args.get("path") or args.get("file") or "").strip('"').strip()
if not raw_target:
    emit("allow")

def resolve_real(target_path, base_dir):
    cur = pathlib.Path(os.path.abspath(os.path.join(str(base_dir), str(target_path))))
    parts = []
    while not cur.exists():
        parent = cur.parent
        if parent == cur:
            break
        parts.insert(0, cur.name)
        cur = parent
    real_base = pathlib.Path(os.path.realpath(str(cur)))
    return real_base.joinpath(*parts) if parts else real_base

ws_list = data.get("workspacePaths") or []
raw_repo = ws_list[0] if (ws_list and os.path.exists(ws_list[0])) else (os.environ.get("AGY_GUARD_REPO_ROOT") or os.getcwd())
repo_root = resolve_real(raw_repo, os.getcwd())
abs_target = resolve_real(raw_target, repo_root)

try:
    rel = abs_target.relative_to(repo_root).as_posix()
except ValueError:
    emit("allow")

def is_harness_internal(rel_path):
    return rel_path in (".artifacts", ".agents") or rel_path.startswith(".artifacts/") or rel_path.startswith(".agents/")

if not rel or is_harness_internal(rel):
    emit("allow")

is_parent = False
tp = str(data.get("transcriptPath") or "")
if tp and os.path.exists(tp):
    try:
        with open(tp, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.strip():
                    obj = json.loads(line)
                    if isinstance(obj, dict) and (obj.get("type") == "USER_INPUT" or obj.get("source") == "USER_EXPLICIT"):
                        is_parent = True
                    break
    except Exception:
        emit("allow")

if not is_parent:
    emit("allow")

spec_path = repo_root / ".artifacts" / "SPEC.md"
plan_path = repo_root / ".artifacts" / "PLAN.md"
spec_txt = spec_path.read_text(encoding="utf-8") if spec_path.exists() else ""
plan_txt = plan_path.read_text(encoding="utf-8") if plan_path.exists() else ""
is_spec_active = bool(spec_txt.strip()) and "_Describe the concrete user or system problem being solved._" not in spec_txt and "<!-- HARNESS_TEMPLATE_UNFILLED" not in spec_txt
is_plan_active = bool(plan_txt.strip()) and "## Slice 1: [Title]" not in plan_txt and "<!-- HARNESS_TEMPLATE_UNFILLED" not in plan_txt

if is_spec_active or is_plan_active:
    emit(
        "deny",
        f"BLOCKED by AGY Harness Source-Edit Guard: Active contract found in .artifacts/SPEC.md or .artifacts/PLAN.md. Top-level coordinator MUST NOT directly edit `{rel}`. Wait for user Proceed and delegate ALL implementation/rework edits to `slice-builder` via `invoke_subagent` or `send_message`.",
    )

def run_git(git_args):
    try:
        res = subprocess.run(["git", "--no-pager", *git_args], cwd=str(repo_root), capture_output=True, text=True, timeout=2.5)
        return res.stdout if res.returncode == 0 else None
    except Exception:
        return None

if (run_git(["rev-parse", "--is-inside-work-tree"]) or "").strip() != "true":
    emit("allow")

HARNESS_BOOTSTRAP_PATHS = {
    ".gitignore",
    "scripts/gate-check.sh",
    "scripts/harness-approval-gate.sh",
    "scripts/harness-source-edit-guard.sh",
}

def skip_background_budget_count(rel_path):
    return is_harness_internal(rel_path) or (rel_path != rel and rel_path in HARNESS_BOOTSTRAP_PATHS)

status_out = run_git(["status", "--porcelain=v1", "-uall"]) or ""
touched = {rel}
untracked = []
for raw_line in status_out.splitlines():
    if len(raw_line) < 4:
        continue
    code = raw_line[:2]
    p = raw_line[3:].strip()
    if " -> " in p:
        p = p.split(" -> ", 1)[1]
    p = p.strip('"').replace("\\", "/")
    if not p or skip_background_budget_count(p):
        continue
    touched.add(p)
    if code == "??":
        untracked.append(p)

if len(touched) > 3:
    emit(
        "deny",
        f"BLOCKED by AGY Harness Source-Edit Guard: Exceeds Tier S file budget ({len(touched)} > 3 non-harness files, target `{rel}`). Escalate to Tier M/L: draft .artifacts/{{SPEC,PLAN}}.md + <ArtifactDir>/harness_plan.md (RequestFeedback=true), wait for Proceed, and delegate implementation to `slice-builder`.",
    )

has_head = run_git(["rev-parse", "--verify", "HEAD"]) is not None
numstat_out = run_git(["diff", "--numstat", "HEAD"] if has_head else ["diff", "--numstat", "--cached"]) or ""
changed_lines = 0
for line in numstat_out.splitlines():
    if not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) < 3:
        continue
    p = parts[-1].strip('"').replace("\\", "/")
    if skip_background_budget_count(p):
        continue
    for n in parts[:2]:
        if n.isdigit():
            changed_lines += int(n)

for uf in untracked:
    full = resolve_real(uf, repo_root)
    try:
        full.relative_to(repo_root)
    except ValueError:
        continue
    if full.is_file():
        raw_bytes = full.read_bytes()
        if b"\x00" not in raw_bytes:
            txt = raw_bytes.decode("utf-8", errors="ignore")
            changed_lines += len(txt.splitlines()) if txt else 0

pending_added = 0
if tool_name in ("write_file", "write_to_file") and isinstance(args.get("Content"), str) and not abs_target.exists():
    pending_added = len(args["Content"].splitlines()) if args["Content"] else 0
elif isinstance(args.get("Replacement"), str):
    rep_lines = len(args["Replacement"].splitlines()) if args["Replacement"] else 0
    tgt_lines = len(args["Target"].splitlines()) if isinstance(args.get("Target"), str) and args["Target"] else 0
    pending_added = max(0, rep_lines - tgt_lines)

if changed_lines + pending_added > 150:
    emit(
        "deny",
        f"BLOCKED by AGY Harness Source-Edit Guard: Exceeds Tier S line budget ({changed_lines + pending_added} > 150 changed lines including `{rel}`). Escalate to Tier M/L: draft .artifacts/{{SPEC,PLAN}}.md + <ArtifactDir>/harness_plan.md (RequestFeedback=true), wait for Proceed, and delegate implementation to `slice-builder`.",
    )

emit("allow")
PY
fi

echo '{"decision":"allow"}'
