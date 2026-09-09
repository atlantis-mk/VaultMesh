import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { expectedTraceability } from './document-governance-lib.mjs';
import { createWork, finishWork, startWork } from './work-lifecycle-lib.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultmesh-work-lifecycle-'));
  fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
  fs.mkdirSync(path.join(root, 'changes'), { recursive: true });
  fs.writeFileSync(path.join(root, 'docs', '00-spec-index.md'), '- 规格修订：`0.1.53-active`\n');
  fs.writeFileSync(path.join(root, 'docs', '03-functional-requirements.md'), '### REQ-TEST-001 Test\n\nAcceptance: `AT-TEST-001`.\n');
  fs.writeFileSync(path.join(root, 'changes', 'archive.json'), '{"version":1,"archives":[]}\n');
  fs.writeFileSync(path.join(root, 'docs', '08-traceability.md'), expectedTraceability(root));
  return root;
}

test('creates and finishes one-file schema-v2 Work without archiving it', () => {
  const root = fixture();
  const workId = 'CHG-2026-901-minimal-test';
  createWork({ root, workId, title: 'Minimal', type: 'governance', goal: 'Preserve a boundary decision' });
  assert.deepEqual(fs.readdirSync(path.join(root, 'changes', workId)), ['change.yaml']);
  assert.equal(startWork({ root, workId }).status, 'Active');
  finishWork({ root, workId, runCheck: () => true });
  assert.match(fs.readFileSync(path.join(root, 'changes', workId, 'change.yaml'), 'utf8'), /status: "Done"/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'changes', 'archive.json'), 'utf8')).archives.length, 0);
});

test('keeps legacy Work completion and archive compatible', () => {
  const root = fixture();
  const workId = 'CHG-2026-902-legacy';
  fs.mkdirSync(path.join(root, 'changes', workId));
  fs.writeFileSync(path.join(root, 'changes', workId, 'change.yaml'), `id: "${workId}"\ntitle: "Legacy"\ntype: "governance"\nstatus: "Implementing"\nspec_revision: "0.1.52-active"\ntarget_release: null\nrequirements: []\ntests: []\nadrs: []\ncontext_refs: []\nrelated_changes: []\naffected_surfaces: []\naffected_formats: []\naffected_versions: []\nsecurity_impact: "none"\nmigration: "none"\nsupersedes: []\n`);
  finishWork({ root, workId, runCheck: () => true, now: () => new Date('2026-09-09T00:00:00.000Z') });
  assert.match(fs.readFileSync(path.join(root, 'changes', workId, 'change.yaml'), 'utf8'), /status: "Verified"/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'changes', 'archive.json'), 'utf8')).archives.length, 1);
});

test('rolls back a legacy archive when post-completion validation fails', () => {
  const root = fixture();
  const workId = 'CHG-2026-903-legacy-rollback';
  fs.mkdirSync(path.join(root, 'changes', workId));
  fs.writeFileSync(path.join(root, 'changes', workId, 'change.yaml'), `id: "${workId}"\ntitle: "Legacy"\ntype: "governance"\nstatus: "Implementing"\nspec_revision: "0.1.52-active"\ntarget_release: null\nrequirements: []\ntests: []\nadrs: []\ncontext_refs: []\nrelated_changes: []\naffected_surfaces: []\naffected_formats: []\naffected_versions: []\nsecurity_impact: "none"\nmigration: "none"\nsupersedes: []\n`);
  let checks = 0;
  assert.throws(() => finishWork({ root, workId, runCheck: () => ++checks === 1 }), /post-completion/);
  assert.match(fs.readFileSync(path.join(root, 'changes', workId, 'change.yaml'), 'utf8'), /status: "Implementing"/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'changes', 'archive.json'), 'utf8')).archives.length, 0);
});
