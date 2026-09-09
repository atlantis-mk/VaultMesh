import fs from 'node:fs';
import path from 'node:path';
import { archiveWork } from './work-archive-lib.mjs';
import { currentSpecRevision, expectedTraceability, isWorkV2, parseChangeYamlText, replaceYamlScalar } from './document-governance-lib.mjs';

export const ALLOWED_TYPES = new Set(['feature', 'bug', 'security', 'dependency', 'migration', 'technical_debt', 'governance']);
export const ALLOWED_CHECKS = new Set(['docs:check', 'scripts:test', 'test', 'typecheck', 'tauri:build']);

function yamlPath(root, workId) {
  if (!/^[A-Z]+-\d{4}-\d{3}[a-z0-9-]*$/.test(workId)) throw new Error(`invalid Work ID: ${workId}`);
  return path.join(root, 'changes', workId, 'change.yaml');
}

export function createWork({ root, workId, title, type, goal }) {
  if (!ALLOWED_TYPES.has(type)) throw new Error(`type must be one of: ${[...ALLOWED_TYPES].join(', ')}`);
  if (!title?.trim() || !goal?.trim()) throw new Error('title and goal are required');
  const target = yamlPath(root, workId);
  if (fs.existsSync(path.dirname(target))) throw new Error(`Work directory already exists: changes/${workId}`);
  fs.mkdirSync(path.dirname(target));
  fs.writeFileSync(target, `schema: "2"\nid: ${JSON.stringify(workId)}\ntitle: ${JSON.stringify(title.trim())}\ntype: ${JSON.stringify(type)}\nstatus: "Draft"\nspec_revision: ${JSON.stringify(currentSpecRevision(root))}\ntarget_release: null\ngoal: ${JSON.stringify(goal.trim())}\nrequirements: []\ntests: []\nadrs: []\ncontext_refs: []\nrelated_changes: []\nboundaries: []\nrisks: []\nnext: []\n`);
  return target;
}

export function startWork({ root, workId, accept = false }) {
  const target = yamlPath(root, workId);
  const original = fs.readFileSync(target, 'utf8');
  const change = parseChangeYamlText(original, path.relative(root, target));
  const status = isWorkV2(change)
    ? (change.status === 'Draft' ? 'Active' : null)
    : (change.status === 'Accepted' || (accept && change.status === 'Draft') ? 'Implementing' : null);
  if (!status) throw new Error(`${workId}: status ${change.status} cannot start`);
  fs.writeFileSync(target, replaceYamlScalar(original, 'status', status));
  return { target, original, status };
}

export function selectApplicableChecks(change, additional = []) {
  for (const check of additional) if (!ALLOWED_CHECKS.has(check)) throw new Error(`unsupported check: ${check}`);
  const surface = [...(change.boundaries ?? []), ...(change.affected_surfaces ?? [])].join(' ').toLowerCase();
  const checks = new Set(['docs:check']);
  if (/(documentation|governance|script|release|workflow)/.test(surface)) checks.add('scripts:test');
  if (/(core|tauri|desktop|renderer|extension|browser)/.test(surface)) checks.add('test');
  for (const check of additional) checks.add(check);
  return [...checks];
}

function runChecks(workId, checks, runCheck) {
  for (const check of checks) if (!runCheck(check)) throw new Error(`${workId}: check failed: pnpm ${check}`);
}

export function finishWork({ root, workId, additionalChecks = [], runCheck, now = () => new Date() }) {
  const target = yamlPath(root, workId);
  const original = fs.readFileSync(target, 'utf8');
  const change = parseChangeYamlText(original, path.relative(root, target));
  const v2 = isWorkV2(change);
  if (v2 && change.status !== 'Active') throw new Error(`${workId}: only Active schema-v2 Work can finish`);
  if (!v2 && change.status !== 'Implementing') throw new Error(`${workId}: only Implementing legacy Work can finish`);
  const tracePath = path.join(root, 'docs', '08-traceability.md');
  const priorTrace = fs.readFileSync(tracePath);
  const archivePath = path.join(root, 'changes', 'archive.json');
  const priorArchive = v2 ? null : fs.readFileSync(archivePath);
  runChecks(workId, selectApplicableChecks(change, additionalChecks), runCheck);
  try {
    fs.writeFileSync(target, replaceYamlScalar(original, 'status', v2 ? 'Done' : 'Verified'));
    if (!v2) archiveWork({ root, workId, status: 'Verified', archivedAt: now().toISOString() });
    fs.writeFileSync(tracePath, expectedTraceability(root));
    if (!runCheck('docs:check')) throw new Error(`${workId}: post-completion documentation validation failed`);
    return { work_id: workId, status: v2 ? 'Done' : 'Verified' };
  } catch (error) {
    fs.writeFileSync(target, original);
    fs.writeFileSync(tracePath, priorTrace);
    if (priorArchive !== null) fs.writeFileSync(archivePath, priorArchive);
    throw error;
  }
}
