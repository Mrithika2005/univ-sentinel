#!/usr/bin/env node
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const dir = dirname(fileURLToPath(import.meta.url));
console.log('Starting Sentinel SDK...');
execSync('npx tsx server.ts', { cwd: dir, stdio: 'inherit' });
