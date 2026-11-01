// Общие помощники тестов.
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Классический скрипт браузера (UMD: регистрирует себя в self/this) —
// исполняем как скрипт в текущем контексте и возвращаем globalThis.
export function loadScript(file) {
  vm.runInThisContext(readFileSync(path.join(ROOT, file), 'utf8'), { filename: file });
  return globalThis;
}
