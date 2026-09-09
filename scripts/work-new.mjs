#!/usr/bin/env node
import { createWork } from './work-lifecycle-lib.mjs';
const args = process.argv.slice(2).filter((arg) => arg !== '--');
const value = (name) => args[args.indexOf(name) + 1] ?? null;
try {
  if (!args[0] || !value('--title') || !value('--type') || !value('--goal')) throw new Error('usage: pnpm work:new -- <WORK-ID> --title <title> --type <type> --goal <cross-task-or-controlled-boundary>');
  createWork({ root: process.cwd(), workId: args[0], title: value('--title'), type: value('--type'), goal: value('--goal') });
  console.log(`created changes/${args[0]}`);
} catch (error) { console.error(error.message); process.exit(1); }
