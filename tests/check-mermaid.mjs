// Parse every ```mermaid block in the given Markdown files; exit 1 if any fail.
// Usage (needs `npm i mermaid@11 jsdom`): node tests/check-mermaid.mjs README.md
import { JSDOM } from 'jsdom';
import fs from 'fs';

const dom = new JSDOM('<!doctype html><body></body>');
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator, configurable: true });

const mermaid = (await import('mermaid')).default;
mermaid.initialize({ startOnLoad: false });

let total = 0;
let bad = 0;
for (const file of process.argv.slice(2)) {
  const md = fs.readFileSync(file, 'utf8');
  for (const m of md.matchAll(/```mermaid\n([\s\S]*?)```/g)) {
    total++;
    const first = m[1].trim().split('\n')[0];
    try {
      await mermaid.parse(m[1]);
      console.log(`ok   ${file} #${total}: ${first}`);
    } catch (e) {
      bad++;
      console.log(`FAIL ${file} #${total}: ${first}\n     ${String(e.message || e).split('\n').slice(0, 4).join(' | ')}`);
    }
  }
}
console.log(`\n${total} diagrams, ${bad} failed`);
process.exit(bad ? 1 : 0);
