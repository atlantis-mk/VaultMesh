#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { expectedTraceability } from './document-governance-lib.mjs';

const root = process.cwd();
const target = path.join(root, 'docs', '08-traceability.md');
const content = expectedTraceability(root);
const unchanged = fs.existsSync(target) && fs.readFileSync(target, 'utf8') === content;
if (!unchanged) fs.writeFileSync(target, content);
console.log(unchanged ? 'Traceability is current' : 'generated docs/08-traceability.md');
