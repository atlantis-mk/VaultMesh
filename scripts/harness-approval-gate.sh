#!/bin/bash
# harness-approval-gate.sh — Antigravity PreToolUse Software 1.0 Gate
#
# Enforces human-in-the-loop confirmation (Proceed click or explicit user turn)
# whenever .artifacts/SPEC.md or .artifacts/PLAN.md core contract sections are
# created or substantively modified, blocking premature invoke_subagent(slice-builder)
# or swarm(add) while allowing read-only subagents, checkbox/status updates, and
# post-approval non-contract implementation notes / guardrails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -t 0 ]; then
  HOOK_STDIN="{}"
else
  HOOK_STDIN="$(cat)"
fi

export AGY_HARNESS_SCRIPT_REPO_ROOT="$SCRIPT_REPO_ROOT"
export AGY_HARNESS_HOOK_STDIN="$HOOK_STDIN"

if command -v node >/dev/null 2>&1; then
  exec node -e '
"use strict";
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const emit = (decision, reason) => {
  const out = reason ? { decision, reason } : { decision };
  process.stdout.write(JSON.stringify(out) + "\n");
  process.exit(0);
};

let input = {};
try {
  input = JSON.parse(process.env.AGY_HARNESS_HOOK_STDIN || "{}");
} catch {
  emit("allow");
}

const toolCall = input.toolCall || {};
const toolName = String(toolCall.name || "");
const args = toolCall.args || {};

const isGatedSubagent =
  toolName === "invoke_subagent" &&
  ["slice-builder", "self"].includes(String(args.TypeName || "").trim());
const isGatedSwarm =
  toolName === "swarm" && String(args.action || "").trim() === "add";
const isGated = isGatedSubagent || isGatedSwarm;

const rawWorkspaceRoot =
  (Array.isArray(input.workspacePaths) && input.workspacePaths[0]) ||
  process.env.AGY_HARNESS_SCRIPT_REPO_ROOT;
let workspaceRoot = rawWorkspaceRoot;
try {
  workspaceRoot = fs.realpathSync(rawWorkspaceRoot);
} catch {}

const specPath = path.join(workspaceRoot, ".artifacts", "SPEC.md");
const planPath = path.join(workspaceRoot, ".artifacts", "PLAN.md");

if (!fs.existsSync(specPath) || !fs.existsSync(planPath)) {
  if (!isGated) emit("allow");
  emit(
    "deny",
    "BLOCKED by AGY Harness Approval Gate: .artifacts/SPEC.md and .artifacts/PLAN.md must both exist and be approved by the user before invoking slice-builder or swarm."
  );
}

const specContent = fs.readFileSync(specPath, "utf8");
const planContent = fs.readFileSync(planPath, "utf8");

const hasTemplatePlaceholder =
  !specContent.trim() ||
  !planContent.trim() ||
  specContent.includes("_Describe the concrete user or system problem being solved._") ||
  specContent.includes("<!-- HARNESS_TEMPLATE_UNFILLED") ||
  planContent.includes("## Slice 1: [Title]") ||
  planContent.includes("<!-- HARNESS_TEMPLATE_UNFILLED");

if (hasTemplatePlaceholder) {
  if (!isGated) emit("allow");
  emit(
    "deny",
    "BLOCKED by AGY Harness Approval Gate: .artifacts/SPEC.md or .artifacts/PLAN.md still contains unfilled template placeholders. Draft the contract, sync <ArtifactDir>/harness_plan.md with ArtifactMetadata.RequestFeedback=true, stop your turn, and wait for the user to click Proceed."
  );
}

const normalizeContract = (text) => {
  const cleaned = text
    .replace(/\r\n/g, "\n")
    .replace(/<!--\s*non-contract\s*-->[\s\S]*?<!--\s*\/non-contract\s*-->/gi, "");
  const nonContractHeadingRe =
    /^##\s+(?:Implementation Notes(?:\s*\/\s*Guardrails)?|Guardrails|实施备注|风险护栏)\b/i;
  const out = [];
  let skipping = false;
  for (const rawLine of cleaned.split("\n")) {
    if (/^##\s+/.test(rawLine)) {
      skipping = nonContractHeadingRe.test(rawLine);
    }
    if (skipping) continue;
    const normalized = rawLine
      .replace(/^(\s*-\s*)\[[ xX\/-]\](\s+)/, "$1[ ]$2")
      .replace(/^(\s*-\s*\*\*)(?:Status|状态)(:\*\*\s*).+$/, "$1Status$2<STATUS>");
    if (normalized.trim().length > 0) {
      out.push(normalized);
    }
  }
  return out.join("\n");
};

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const semanticHash = sha256(
  "SPEC\n" + normalizeContract(specContent) + "\nPLAN\n" + normalizeContract(planContent)
);

const stateDir =
  process.env.AGY_HARNESS_STATE_DIR ||
  process.env.PLUGIN_DATA ||
  path.join(os.tmpdir(), "agy-harness-approvals");
const stateKey = sha256(workspaceRoot + "::" + String(input.conversationId || "default")).slice(0, 24);
const statePath = path.join(stateDir, stateKey + ".json");

let state = null;
if (fs.existsSync(statePath)) {
  try {
    state = JSON.parse(fs.readFileSync(statePath, "utf8"));
  } catch {
    state = null;
  }
}

let lastUserStep = null;
let modifiedAfterUserInTranscript = false;
const transcriptPath = input.transcriptPath ? String(input.transcriptPath) : "";

if (transcriptPath && fs.existsSync(transcriptPath)) {
  const lines = fs.readFileSync(transcriptPath, "utf8").split(/\r?\n/).filter(Boolean);
  let lastUserIdx = -1;
  const parsed = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      const obj = JSON.parse(lines[i]);
      parsed.push(obj);
      if (obj && (obj.type === "USER_INPUT" || obj.source === "USER_EXPLICIT")) {
        lastUserIdx = parsed.length - 1;
      }
    } catch {
      // Ignore malformed line
    }
  }
  if (lastUserIdx >= 0) {
    lastUserStep = parsed[lastUserIdx];
    const fileWriteTools = new Set([
      "write_file",
      "edit_file",
      "write_to_file",
      "replace_file_content",
      "multi_replace_file_content",
    ]);
    for (let j = lastUserIdx + 1; j < parsed.length; j++) {
      const step = parsed[j];
      if (!step || !Array.isArray(step.tool_calls)) continue;
      for (const tc of step.tool_calls) {
        const tcName = String((tc && tc.name) || "");
        const tcArgs = (tc && tc.args) || {};
        if (fileWriteTools.has(tcName)) {
          const targetPath = String(tcArgs.Path || tcArgs.TargetFile || "").replace(/^"+|"+$/g, "");
          if (/\.artifacts[\\/]+(SPEC|PLAN)\.md$/.test(targetPath)) {
            modifiedAfterUserInTranscript = true;
          }
        } else if (tcName === "run_command") {
          const cmd = String(tcArgs.CommandLine || "");
          if (/\.artifacts[\\/]+(SPEC|PLAN)\.md/.test(cmd)) {
            modifiedAfterUserInTranscript = true;
          }
        }
      }
    }
  }
}

let isUnapprovedArtifactComment = false;
if (lastUserStep) {
  const lastUserContent = String(lastUserStep.content || "");
  isUnapprovedArtifactComment =
    lastUserContent.includes("Comments on artifact URI:") &&
    !lastUserContent.includes("The user has approved this document.");

  if (isUnapprovedArtifactComment) {
    if (!isGated) emit("allow");
    emit(
      "deny",
      "BLOCKED by AGY Harness Approval Gate: The user commented on the review artifact without approving it. Revise .artifacts/SPEC.md or .artifacts/PLAN.md as requested, update <ArtifactDir>/harness_plan.md with RequestFeedback=true, end your turn, and wait for user approval."
    );
  }
}

if (state && state.approvedHash === semanticHash) {
  emit("allow");
}

if (!lastUserStep || !lastUserStep.created_at) {
  if (!isGated) emit("allow");
  emit(
    "force_ask",
    "AGY Harness: Confirm starting implementation against current .artifacts/SPEC.md and .artifacts/PLAN.md?"
  );
}

const lastUserTimeMs = Date.parse(lastUserStep.created_at);
const maxContractMtimeMs = Math.max(
  fs.statSync(specPath).mtimeMs,
  fs.statSync(planPath).mtimeMs
);

if (
  !Number.isFinite(lastUserTimeMs) ||
  maxContractMtimeMs > lastUserTimeMs ||
  modifiedAfterUserInTranscript
) {
  if (!isGated) emit("allow");
  emit(
    "deny",
    "BLOCKED by AGY Harness Approval Gate: .artifacts/SPEC.md or .artifacts/PLAN.md was created or substantively modified after the last user confirmation. Sync <ArtifactDir>/harness_plan.md with ArtifactMetadata.RequestFeedback=true, stop calling tools to end your turn, and wait for the user to click Proceed (or confirm) in the next turn."
  );
}

fs.mkdirSync(stateDir, { recursive: true });
fs.writeFileSync(
  statePath,
  JSON.stringify(
    {
      approvedHash: semanticHash,
      approvedAtMs: Date.now(),
      approvedStepIdx: lastUserStep.step_index ?? 0,
    },
    null,
    2
  ) + "\n"
);
emit("allow");
'
fi

if command -v python3 >/dev/null 2>&1; then
  exec python3 -c '
import datetime, hashlib, json, os, pathlib, re, sys, tempfile

def emit(decision, reason=None):
    out = {"decision": decision}
    if reason:
        out["reason"] = reason
    sys.stdout.write(json.dumps(out) + "\n")
    sys.exit(0)

try:
    data = json.loads(os.environ.get("AGY_HARNESS_HOOK_STDIN", "{}") or "{}")
except Exception:
    emit("allow")

tc = data.get("toolCall") or {}
tool_name = str(tc.get("name") or "")
args = tc.get("args") or {}

is_sub = tool_name == "invoke_subagent" and str(args.get("TypeName") or "").strip() in ("slice-builder", "self")
is_swm = tool_name == "swarm" and str(args.get("action") or "").strip() == "add"
is_gated = is_sub or is_swm

ws_list = data.get("workspacePaths") or []
raw_ws_root = ws_list[0] if ws_list else os.environ["AGY_HARNESS_SCRIPT_REPO_ROOT"]
try:
    ws_root = pathlib.Path(os.path.realpath(str(raw_ws_root)))
except Exception:
    ws_root = pathlib.Path(raw_ws_root)
spec_path = ws_root / ".artifacts" / "SPEC.md"
plan_path = ws_root / ".artifacts" / "PLAN.md"

if not spec_path.exists() or not plan_path.exists():
    if not is_gated:
        emit("allow")
    emit("deny", "BLOCKED by AGY Harness Approval Gate: .artifacts/SPEC.md and .artifacts/PLAN.md must both exist and be approved by the user before invoking slice-builder or swarm.")

spec_txt = spec_path.read_text(encoding="utf-8")
plan_txt = plan_path.read_text(encoding="utf-8")

if (not spec_txt.strip() or not plan_txt.strip()
    or "_Describe the concrete user or system problem being solved._" in spec_txt
    or "<!-- HARNESS_TEMPLATE_UNFILLED" in spec_txt
    or "## Slice 1: [Title]" in plan_txt
    or "<!-- HARNESS_TEMPLATE_UNFILLED" in plan_txt):
    if not is_gated:
        emit("allow")
    emit("deny", "BLOCKED by AGY Harness Approval Gate: .artifacts/SPEC.md or .artifacts/PLAN.md still contains unfilled template placeholders. Sync <ArtifactDir>/harness_plan.md with RequestFeedback=true, end your turn, and wait for the user to click Proceed.")

def norm(t):
    cleaned = re.sub(
        r"<!--\s*non-contract\s*-->[\s\S]*?<!--\s*/non-contract\s*-->",
        "",
        t.replace("\r\n", "\n"),
        flags=re.IGNORECASE,
    )
    non_contract_re = re.compile(
        r"^##\s+(?:Implementation Notes(?:\s*/\s*Guardrails)?|Guardrails|实施备注|风险护栏)\b",
        re.IGNORECASE,
    )
    lines = []
    skipping = False
    for ln in cleaned.split("\n"):
        if re.match(r"^##\s+", ln):
            skipping = bool(non_contract_re.match(ln))
        if skipping:
            continue
        ln = re.sub(r"^(\s*-\s*)\[[ xX/-]\](\s+)", r"\1[ ]\2", ln)
        ln = re.sub(r"^(\s*-\s*\*\*)(?:Status|状态)(:\*\*\s*).+$", r"\1Status\2<STATUS>", ln)
        if ln.strip():
            lines.append(ln)
    return "\n".join(lines)

sem_hash = hashlib.sha256(("SPEC\n" + norm(spec_txt) + "\nPLAN\n" + norm(plan_txt)).encode("utf-8")).hexdigest()
state_dir = pathlib.Path(os.environ.get("AGY_HARNESS_STATE_DIR") or os.environ.get("PLUGIN_DATA") or (pathlib.Path(tempfile.gettempdir()) / "agy-harness-approvals"))
state_key = hashlib.sha256((str(ws_root) + "::" + str(data.get("conversationId") or "default")).encode("utf-8")).hexdigest()[:24]
state_path = state_dir / f"{state_key}.json"

state = None
if state_path.exists():
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        state = None

last_user = None
mod_after = False
tp = data.get("transcriptPath")
if tp and pathlib.Path(tp).exists():
    parsed = []
    last_idx = -1
    for raw in pathlib.Path(tp).read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
            parsed.append(obj)
            if obj.get("type") == "USER_INPUT" or obj.get("source") == "USER_EXPLICIT":
                last_idx = len(parsed) - 1
        except Exception:
            pass
    if last_idx >= 0:
        last_user = parsed[last_idx]
        file_write_tools = {
            "write_file",
            "edit_file",
            "write_to_file",
            "replace_file_content",
            "multi_replace_file_content",
        }
        for step in parsed[last_idx + 1:]:
            for call in (step.get("tool_calls") or []):
                tc_name = str((call or {}).get("name") or "")
                tc_args = (call or {}).get("args") or {}
                if tc_name in file_write_tools:
                    target_path = str(tc_args.get("Path") or tc_args.get("TargetFile") or "").strip("\"")
                    if re.search(r"\.artifacts[\\/]+(SPEC|PLAN)\.md$", target_path):
                        mod_after = True
                elif tc_name == "run_command":
                    if re.search(r"\.artifacts[\\/]+(SPEC|PLAN)\.md", str(tc_args.get("CommandLine") or "")):
                        mod_after = True

if last_user:
    content = str(last_user.get("content") or "")
    if "Comments on artifact URI:" in content and "The user has approved this document." not in content:
        if not is_gated:
            emit("allow")
        emit("deny", "BLOCKED by AGY Harness Approval Gate: The user commented on the review artifact without approving it. Revise .artifacts/SPEC.md or .artifacts/PLAN.md, update <ArtifactDir>/harness_plan.md with RequestFeedback=true, end your turn, and wait for user approval.")

if state and state.get("approvedHash") == sem_hash:
    emit("allow")

if not last_user or not last_user.get("created_at"):
    if not is_gated:
        emit("allow")
    emit("force_ask", "AGY Harness: Confirm starting implementation against current .artifacts/SPEC.md and .artifacts/PLAN.md?")

ts_raw = str(last_user["created_at"]).replace("Z", "+00:00")
last_ms = datetime.datetime.fromisoformat(ts_raw).timestamp() * 1000.0
max_mtime_ms = max(spec_path.stat().st_mtime, plan_path.stat().st_mtime) * 1000.0

if max_mtime_ms > last_ms or mod_after:
    if not is_gated:
        emit("allow")
    emit("deny", "BLOCKED by AGY Harness Approval Gate: .artifacts/SPEC.md or .artifacts/PLAN.md was created or substantively modified after the last user confirmation. Sync <ArtifactDir>/harness_plan.md with ArtifactMetadata.RequestFeedback=true, stop calling tools to end your turn, and wait for the user to click Proceed (or confirm) in the next turn.")

state_dir.mkdir(parents=True, exist_ok=True)
state_path.write_text(json.dumps({"approvedHash": sem_hash, "approvedStepIdx": last_user.get("step_index", 0)}, indent=2) + "\n", encoding="utf-8")
emit("allow")
'
fi

echo '{"decision":"force_ask","reason":"AGY Harness: Confirm starting implementation against current .artifacts/SPEC.md and .artifacts/PLAN.md?"}'
