import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const exhibits = readFileSync(new URL('../src/exhibits.ts', import.meta.url), 'utf8');
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const studentCopy = `${html}\n${exhibits}\n${readme}`;

test('counts cost iterations separately from ExpandKey calls', () => {
  assert.match(studentCopy, /2<sup>cost<\/sup> cost iterations/u);
  assert.match(studentCopy, /two full ExpandKey calls/u);
  assert.doesNotMatch(studentCopy, /key-expansion rounds/u);
});

test('scopes the 72-byte behavior and rejects silent truncation advice', () => {
  assert.match(studentCopy, /bcryptjs with current \$2b\$ behavior/u);
  assert.match(studentCopy, /reject an over-limit input/u);
  assert.doesNotMatch(studentCopy, /truncate-and-warn/u);
});

test('does not turn a dated minimum or local latency target into safety', () => {
  assert.match(studentCopy, /Meets OWASP’s Nov 2026 minimum/u);
  assert.match(studentCopy, /not a security boundary/u);
  assert.match(studentCopy, /concurrency, abuse\/DoS budget, and attacker assumptions/u);
  assert.doesNotMatch(studentCopy, /Safe zone/u);
  assert.doesNotMatch(studentCopy, /same cost per hash/u);
});
