#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { finishWork } from './work-lifecycle-lib.mjs';
const args = process.argv.slice(2).filter((arg) => arg !== '--');
const workId = args[0];
const checks = args.flatMap((arg, index) => arg === '--check' ? [args[index + 1]] : []).filter(Boolean);
try {
  if (!workId) throw new Error('usage: pnpm work:finish -- <WORK-ID> [--check <docs:check|scripts:test|test|typecheck|tauri:build>]...');
  finishWork({ root: process.cwd(), workId, additionalChecks: checks, runCheck: (name) => spawnSync('pnpm', [name], { cwd: process.cwd(), stdio: 'inherit' }).status === 0 });
  console.log(`completed ${workId}`);
} catch (error) { console.error(error.message); process.exit(1); }
