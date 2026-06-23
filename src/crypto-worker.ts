/**
 * crypto-worker.ts — Runs every CPU-heavy crypto operation off the main
 * thread so the UI never freezes. bcrypt's key-setup is deliberately slow;
 * running it synchronously on the main thread (as the original demo did)
 * stalls rendering for seconds and prevents spinners from even animating.
 *
 * Each request carries an `id`; each reply echoes it back so the client can
 * match responses to promises. Timings are measured *inside* the worker,
 * around the synchronous primitive, so the benchmark numbers are accurate
 * and uncontaminated by message-passing latency.
 */

import bcrypt from 'bcryptjs';
import { md5 } from './lib.ts';

type Req =
  | { id: number; op: 'hash'; password: string; cost: number }
  | { id: number; op: 'compare'; password: string; hash: string }
  | { id: number; op: 'md5'; text: string }
  | { id: number; op: 'pbkdf2'; password: string; iterations: number };

interface Res {
  id: number;
  ok: boolean;
  result?: unknown;
  timeMs?: number;
  error?: string;
}

// The worker global. Typed minimally to avoid pulling in the conflicting
// "webworker" lib alongside "dom" (both define `self`, `postMessage`, etc.).
interface WorkerScope {
  onmessage: ((e: MessageEvent<Req>) => void) | null;
  postMessage(message: Res): void;
}
const ctx = self as unknown as WorkerScope;

ctx.onmessage = async (e: MessageEvent<Req>): Promise<void> => {
  const msg = e.data;
  try {
    switch (msg.op) {
      case 'hash': {
        const t0 = performance.now();
        const salt = bcrypt.genSaltSync(msg.cost);
        const hash = bcrypt.hashSync(msg.password, salt);
        reply({ id: msg.id, ok: true, result: hash, timeMs: performance.now() - t0 });
        break;
      }
      case 'compare': {
        const t0 = performance.now();
        const match = bcrypt.compareSync(msg.password, msg.hash);
        reply({ id: msg.id, ok: true, result: match, timeMs: performance.now() - t0 });
        break;
      }
      case 'md5': {
        reply({ id: msg.id, ok: true, result: md5(msg.text) });
        break;
      }
      case 'pbkdf2': {
        const t0 = performance.now();
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
          'raw', enc.encode(msg.password), 'PBKDF2', false, ['deriveBits'],
        );
        await crypto.subtle.deriveBits(
          { name: 'PBKDF2', salt: enc.encode('demo-fixed-salt-16'), iterations: msg.iterations, hash: 'SHA-256' },
          keyMaterial,
          256,
        );
        reply({ id: msg.id, ok: true, timeMs: performance.now() - t0 });
        break;
      }
    }
  } catch (err) {
    reply({ id: msg.id, ok: false, error: err instanceof Error ? err.message : String(err) });
  }
};

function reply(res: Res): void {
  ctx.postMessage(res);
}
