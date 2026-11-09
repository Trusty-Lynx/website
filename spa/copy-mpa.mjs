
import { cpSync, mkdirSync, readdirSync, rmSync } from 'node:fs';

rmSync('dev-mpa', { recursive: true, force: true });
mkdirSync('dev-mpa');
for (const file of readdirSync('..')) {
  if (/\.(html|js|css|png)$/.test(file)) {
    cpSync('../' + file, 'dev-mpa/' + file);
  }
}
