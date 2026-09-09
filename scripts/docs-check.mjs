import fs from 'node:fs';
import path from 'node:path';
import { validateArchiveManifest } from './work-archive-lib.mjs';
import { currentSpecRevision, expectedTraceability, isWorkV2, parseChangeYamlText, readChanges, V2_KEYS, walkFiles } from './document-governance-lib.mjs';

const ROOT = process.cwd();
const DOC_DIRS = ['docs', 'specs', 'adr', 'changes', 'releases'];
const TYPES = new Set(['feature', 'bug', 'security', 'dependency', 'migration', 'technical_debt', 'governance']);
const V2_STATUSES = new Set(['Draft', 'Active', 'Done', 'Rejected']);
const LEGACY_STATUSES = new Set(['Draft', 'Accepted', 'Implementing', 'Verified', 'Released', 'Rejected']);
const LEGACY_KEYS = new Set(['id', 'title', 'type', 'status', 'spec_revision', 'target_release', 'requirements', 'tests', 'adrs', 'context_refs', 'related_changes', 'affected_surfaces', 'affected_formats', 'affected_versions', 'security_impact', 'migration', 'supersedes']);
const REMOVED_SOURCE_PREFIXES = ['apps/desktop', 'apps/desktop-cli', 'apps/macos', 'apps/macos-cli', 'apps/windows', 'apps/native-host', 'crates/electron-bridge'];
const RETIRED_COMMANDS = new Set(['electron:dev', 'electron:build', 'electron:make', 'electron:test', 'electron:typecheck', 'native:macos:contract-test', 'native:macos:build', 'native:macos:build:release', 'native:macos:launch', 'native:macos:browser-contract', 'verify:native-browser-parity']);

function setDifference(left, right) { return [...left].filter((item) => !right.has(item)); }
function fromRoot(file) { return path.relative(ROOT, file).split(path.sep).join('/'); }

function validatePaths(markdownFiles, archivedIds) {
  const errors = [];
  const rootPrefix = /^(docs|specs|adr|changes|releases|apps|crates|packages|scripts)\//;
  for (const file of markdownFiles) {
    for (const match of fs.readFileSync(file, 'utf8').matchAll(/`([^`\n]+)`/g)) {
      const token = match[1].replace(/[：，。；、,.;:]$/, '');
      if (/^(https?:|N\/A$)|[<>{}*]|^releases\/vX/.test(token) || REMOVED_SOURCE_PREFIXES.some((prefix) => token === prefix || token.startsWith(`${prefix}/`))) continue;
      let target = null;
      if (token.startsWith('../') || token.startsWith('./')) target = path.resolve(path.dirname(file), token.split('#')[0]);
      else if (rootPrefix.test(token)) target = path.resolve(ROOT, token.split('#')[0]);
      else if (fromRoot(file) === 'docs/00-spec-index.md' && /^\d{2}-.*\.md$/.test(token)) target = path.resolve(ROOT, 'docs', token);
      else if (['releases/README.md', 'changes/README.md'].includes(fromRoot(file)) && token.startsWith('_template')) target = path.resolve(path.dirname(file), token);
      if (target && !fs.existsSync(target)) {
        const legacyWork = fromRoot(file).match(/^changes\/([^/]+)\//)?.[1];
        if (!(legacyWork && archivedIds.has(legacyWork) && /^(apps|crates|packages)\//.test(fromRoot(target)))) errors.push(`${fromRoot(file)}: ${token}`);
      }
    }
  }
  return errors;
}

function validateContextRef(reference, file) {
  const [targetPath, selector] = reference.split(/#(.*)/s);
  if (!targetPath || path.isAbsolute(targetPath) || targetPath.split('/').includes('..')) return [`${file}: context_refs must use root-relative paths: ${reference}`];
  if (/^changes\/(?!_template\/)/.test(targetPath)) return [`${file}: other Work must use related_changes: ${reference}`];
  const target = path.join(ROOT, targetPath);
  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) return [`${file}: context_refs path does not exist: ${reference}`];
  if (selector === '') return [`${file}: context_refs selector is empty: ${reference}`];
  if (selector && !fs.readFileSync(target, 'utf8').includes(selector)) return [`${file}: context_refs selector not found: ${reference}`];
  return [];
}

const markdownFiles = ['AGENTS.md', ...DOC_DIRS.flatMap((directory) => walkFiles(path.join(ROOT, directory))).filter((file) => file.endsWith('.md'))];
const requirementText = fs.readFileSync('docs/03-functional-requirements.md', 'utf8');
const traceText = fs.readFileSync('docs/08-traceability.md', 'utf8');
const requirements = new Set([...requirementText.matchAll(/^### ((?:REQ|NFR)-[A-Z]+(?:-[A-Z]+)*-\d+)/gm)].map((match) => match[1]));
const tests = new Set([...requirementText.matchAll(/`((?:AT|CT)-[A-Z-]+-\d+)`/g)].map((match) => match[1]));
const tracedRequirements = new Set([...traceText.matchAll(/^\| ((?:REQ|NFR)-[A-Z]+(?:-[A-Z]+)*-\d+) \|/gm)].map((match) => match[1]));
const tracedTests = new Set([...traceText.matchAll(/(?:AT|CT)-[A-Z-]+-\d+/g)].map((match) => match[0]));
const archive = JSON.parse(fs.readFileSync('changes/archive.json', 'utf8'));
const archivedIds = new Set(archive.archives.map((entry) => entry.work_id));
const adrIds = new Set(walkFiles(path.join(ROOT, 'adr')).filter((file) => /^\d{4}-.*\.md$/.test(path.basename(file))).map((file) => `ADR-${path.basename(file).slice(0, 4)}`));
const templateFile = 'changes/_template/change.yaml';
const template = parseChangeYamlText(fs.readFileSync(templateFile, 'utf8'), templateFile);
const changes = readChanges(ROOT);
const changeIds = new Map();
const yamlErrors = [];

if (!isWorkV2(template) || JSON.stringify(Object.keys(template).sort()) !== JSON.stringify([...V2_KEYS].sort())) {
  yamlErrors.push(`${templateFile}: must contain exactly the schema-v2 fields`);
}

for (const { file, change } of changes) {
  if (changeIds.has(change.id)) yamlErrors.push(`${file}: duplicate Work ID ${change.id}`);
  else changeIds.set(change.id, file);
  const keys = Object.keys(change).sort();
  const v2 = isWorkV2(change);
  const allowed = v2 ? V2_KEYS : [...LEGACY_KEYS];
  const missing = v2 ? V2_KEYS.filter((key) => !keys.includes(key)) : [];
  const unknown = keys.filter((key) => !allowed.includes(key));
  if (missing.length) yamlErrors.push(`${file}: missing fields ${missing.join(', ')}`);
  if (unknown.length) yamlErrors.push(`${file}: unknown fields ${unknown.join(', ')}`);
  if (!TYPES.has(change.type)) yamlErrors.push(`${file}: invalid type ${change.type}`);
  if (!(v2 ? V2_STATUSES : LEGACY_STATUSES).has(change.status)) yamlErrors.push(`${file}: invalid status ${change.status}`);
  if (v2 && (typeof change.goal !== 'string' || !change.goal.trim())) yamlErrors.push(`${file}: schema-v2 goal is required`);
  for (const field of v2 ? ['requirements', 'tests', 'adrs', 'context_refs', 'related_changes', 'boundaries', 'risks', 'next'] : []) {
    if (!Array.isArray(change[field])) yamlErrors.push(`${file}: ${field} must be a list`);
  }
  if (v2) {
    for (const id of change.requirements ?? []) if (!requirements.has(id)) yamlErrors.push(`${file}: unknown Requirement ${id}`);
    for (const id of change.tests ?? []) if (!tests.has(id)) yamlErrors.push(`${file}: unknown Test ${id}`);
    for (const id of change.adrs ?? []) if (!adrIds.has(id)) yamlErrors.push(`${file}: unknown ADR ${id}`);
    for (const ref of change.context_refs ?? []) yamlErrors.push(...validateContextRef(ref, file));
  }
}
for (const { file, change } of changes) {
  if (!isWorkV2(change)) continue;
  for (const id of [...(change.related_changes ?? []), ...(change.supersedes ?? [])]) {
    if (id === change.id || !changeIds.has(id)) yamlErrors.push(`${file}: unknown or self-referencing related Work ${id}`);
  }
}

const commands = new Set();
for (const file of markdownFiles) for (const match of fs.readFileSync(file, 'utf8').matchAll(/pnpm ([a-z][a-z0-9:.-]+)/g)) commands.add(match[1]);
const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const doneV2 = new Set(changes.filter(({ change }) => isWorkV2(change) && change.status === 'Done').map(({ change }) => change.id));
const releaseErrors = [];
for (const file of walkFiles(path.join(ROOT, 'releases')).filter((item) => /\/v[^/]+\.md$/.test(item))) {
  for (const match of fs.readFileSync(file, 'utf8').matchAll(/\b(?:CHG|BUG|SEC|DEP|MIG)-\d{4}-\d{3}[a-z0-9-]*\b/g)) if (!archivedIds.has(match[0]) && !doneV2.has(match[0])) releaseErrors.push(`${fromRoot(file)}: release references unfinished Work ${match[0]}`);
}

const errors = {
  missing_paths: validatePaths(markdownFiles, archivedIds),
  requirements_not_traced: setDifference(requirements, tracedRequirements),
  trace_without_requirement: setDifference(tracedRequirements, requirements),
  tests_not_traced: setDifference(tests, tracedTests),
  trace_tests_without_requirement: setDifference(tracedTests, tests),
  stale_traceability: traceText === expectedTraceability(ROOT) ? [] : ['docs/08-traceability.md: run pnpm docs:trace'],
  absent_commands: [...commands].filter((command) => command !== 'install' && !RETIRED_COMMANDS.has(command) && !(command in packageJson.scripts)),
  yaml_errors: yamlErrors,
  governance_markers: fs.readFileSync('docs/09-document-governance.md', 'utf8').includes('Direct 是默认路径') && fs.readFileSync('AGENTS.md', 'utf8').includes('Direct change 是默认路径') ? [] : ['missing schema-v2 governance marker'],
  release_references: releaseErrors,
  work_archives: validateArchiveManifest({ root: ROOT, changes: changes.map(({ file, change }) => ({ file, ...change })), baseRef: process.env.VAULTMESH_ARCHIVE_BASE_REF || 'HEAD' }),
};
if (Object.values(errors).some((values) => values.length)) { console.error(JSON.stringify(errors, null, 2)); process.exit(1); }
console.log(`docs:check passed (${markdownFiles.length} Markdown, ${changes.length} Work Packages, ${archivedIds.size} archived legacy Work Packages, ${currentSpecRevision(ROOT)})`);
