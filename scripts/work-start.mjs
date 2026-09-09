#!/usr/bin/env node
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { startWork } from './work-lifecycle-lib.mjs';
const args = process.argv.slice(2).filter((arg) => arg !== '--');
const workId = args.find((arg) => !arg.startsWith('--'));
let mutation;
try {
  if (!workId) throw new Error('usage: pnpm work:start -- <WORK-ID> [--accept-for-legacy-work]');
  mutation = startWork({ root: process.cwd(), workId, accept: args.includes('--accept-for-legacy-work') });
  if (spawnSync('pnpm', ['docs:trace'], { cwd: process.cwd(), stdio: 'inherit' }).status !== 0) throw new Error('pnpm docs:trace failed');
  console.log(`started ${workId}`);
} catch (error) { if (mutation) fs.writeFileSync(mutation.target, mutation.original); console.error(error.message); process.exit(1); }
