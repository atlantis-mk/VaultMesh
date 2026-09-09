import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

export const ARCHIVE_PATH = 'changes/archive.json';
export const COMPLETED_STATUSES = new Set(['Verified', 'Released', 'Rejected']);

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`archived Work must not contain symlinks: ${target}`);
    return entry.isDirectory() ? walk(target) : [target];
  });
}

export function hashFile(file) {
  return `sha256:${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}`;
}

export function collectWorkFiles(root, workId) {
  if (!/^[A-Z]+-\d{4}-\d{3}[a-z0-9-]*$/.test(workId)) throw new Error(`invalid Work ID: ${workId}`);
  const workDirectory = path.join(root, 'changes', workId);
  if (!fs.existsSync(workDirectory) || !fs.statSync(workDirectory).isDirectory()) {
    throw new Error(`Work directory does not exist: changes/${workId}`);
  }
  return Object.fromEntries(walk(workDirectory).sort().map((file) => [
    path.relative(root, file).split(path.sep).join('/'),
    hashFile(file),
  ]));
}

export function readArchiveManifest(root) {
  const manifestPath = path.join(root, ARCHIVE_PATH);
  if (!fs.existsSync(manifestPath)) return { version: 1, archives: [] };
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.version !== 1 || !Array.isArray(manifest.archives)) {
    throw new Error(`${ARCHIVE_PATH}: expected version 1 with an archives array`);
  }
  return manifest;
}

export function archiveWork({ root, workId, status, archivedAt = new Date().toISOString() }) {
  if (!COMPLETED_STATUSES.has(status)) {
    throw new Error(`${workId}: status ${status} is not complete; only Verified, Released, or Rejected Work can be archived`);
  }
  if (Number.isNaN(Date.parse(archivedAt))) throw new Error(`invalid archive timestamp: ${archivedAt}`);

  const manifest = readArchiveManifest(root);
  if (manifest.archives.some((entry) => entry.work_id === workId)) {
    throw new Error(`${workId}: already archived`);
  }
  manifest.archives.push({
    work_id: workId,
    status,
    archived_at: archivedAt,
    files: collectWorkFiles(root, workId),
  });
  fs.writeFileSync(path.join(root, ARCHIVE_PATH), `${JSON.stringify(manifest, null, 2)}\n`);
}

function readBaselineManifest(root, baseRef) {
  if (!baseRef) return null;
  if (/^0+$/.test(baseRef)) return null;
  try {
    const raw = execFileSync('git', ['show', `${baseRef}:${ARCHIVE_PATH}`], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return JSON.parse(raw);
  } catch (error) {
    try {
      execFileSync('git', ['cat-file', '-e', `${baseRef}^{commit}`], {
        cwd: root,
        stdio: 'ignore',
      });
      return null;
    } catch {
      if (baseRef === 'HEAD') return null;
    }
    throw new Error(`${ARCHIVE_PATH}: cannot read archive baseline ${baseRef}: ${error.message}`);
  }
}

export function validateArchiveManifest({ root, changes, baseRef = 'HEAD' }) {
  const errors = [];
  let manifest;
  try {
    manifest = readArchiveManifest(root);
  } catch (error) {
    return [error.message];
  }

  const changesById = new Map(changes.map((change) => [change.id, change]));
  const archivesById = new Map();
  for (const entry of manifest.archives) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      errors.push(`${ARCHIVE_PATH}: archive entries must be objects`);
      continue;
    }
    const keys = Object.keys(entry).sort();
    const expectedKeys = ['archived_at', 'files', 'status', 'work_id'];
    if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)) {
      errors.push(`${ARCHIVE_PATH}: ${entry.work_id ?? '<unknown>'} must contain only ${expectedKeys.join(', ')}`);
      continue;
    }
    if (archivesById.has(entry.work_id)) {
      errors.push(`${ARCHIVE_PATH}: duplicate archive ${entry.work_id}`);
      continue;
    }
    archivesById.set(entry.work_id, entry);

    const change = changesById.get(entry.work_id);
    if (!change) {
      errors.push(`${ARCHIVE_PATH}: unknown Work ${entry.work_id}`);
      continue;
    }
    if (!COMPLETED_STATUSES.has(entry.status) || entry.status !== change.status) {
      errors.push(`${ARCHIVE_PATH}: ${entry.work_id} status ${entry.status} does not match completed Work status ${change.status}`);
    }
    if (typeof entry.archived_at !== 'string' || Number.isNaN(Date.parse(entry.archived_at))) {
      errors.push(`${ARCHIVE_PATH}: ${entry.work_id} has an invalid archived_at timestamp`);
    }
    if (!entry.files || typeof entry.files !== 'object' || Array.isArray(entry.files)) {
      errors.push(`${ARCHIVE_PATH}: ${entry.work_id} files must be an object`);
      continue;
    }

    let actualFiles;
    try {
      actualFiles = collectWorkFiles(root, entry.work_id);
    } catch (error) {
      errors.push(error.message);
      continue;
    }
    if (JSON.stringify(Object.keys(entry.files).sort()) !== JSON.stringify(Object.keys(actualFiles).sort())) {
      errors.push(`${ARCHIVE_PATH}: ${entry.work_id} archived file set changed`);
      continue;
    }
    for (const [file, digest] of Object.entries(entry.files)) {
      if (!/^sha256:[a-f0-9]{64}$/.test(digest) || actualFiles[file] !== digest) {
        errors.push(`${ARCHIVE_PATH}: ${entry.work_id} archived file changed: ${file}`);
      }
    }
  }

  for (const change of changes) {
    if (change.schema !== '2' && COMPLETED_STATUSES.has(change.status) && !archivesById.has(change.id)) {
      errors.push(`${change.file}: completed Work ${change.id} must be archived`);
    }
  }

  let baseline;
  try {
    baseline = readBaselineManifest(root, baseRef);
  } catch (error) {
    errors.push(error.message);
    baseline = null;
  }
  if (baseline?.archives) {
    for (const baselineEntry of baseline.archives) {
      const currentEntry = archivesById.get(baselineEntry.work_id);
      if (!currentEntry || JSON.stringify(currentEntry) !== JSON.stringify(baselineEntry)) {
        errors.push(`${ARCHIVE_PATH}: existing archive ${baselineEntry.work_id} is immutable; create a new Work instead`);
      }
    }
  }
  return errors;
}
