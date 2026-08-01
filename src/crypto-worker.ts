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
  | { id: number; op: 'pbkdf2'; password: string; iterations: number }
  | { id: number; op: 'schedule'; password: string; cost: number }
  | {
      id: number;
      op: 'crack';
      targets: { username: string; hash: string }[];
      candidates: string[];
      budgetMs: number;
    };

interface Res {
  id: number;
  ok: boolean;
  result?: unknown;
  timeMs?: number;
  error?: string;
  /** Present on intermediate updates; the request stays open until a reply omits it. */
  progress?: unknown;
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
      case 'schedule': {
        await runSchedule(msg);
        break;
      }
      case 'crack': {
        runCrack(msg);
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

/**
 * Runs the REAL Eksblowfish key schedule and streams genuine progress.
 *
 * bcryptjs's async `hash()` drives the actual `expensive_key_schedule` loop —
 * `_key(password); _key(salt)` repeated 2^cost times — in ~100 ms slices,
 * invoking its progress callback with `completedRounds / totalRounds` between
 * slices. Nothing here is interpolated: every round number we forward was
 * genuinely executed, and the wall-clock duration is the real cost of the
 * schedule at that cost factor. That is why cost 14 takes ~256x cost 6.
 */
async function runSchedule(msg: { id: number; password: string; cost: number }): Promise<void> {
  const totalRounds = 2 ** msg.cost;
  const salt = bcrypt.genSaltSync(msg.cost);
  const t0 = performance.now();

  const hash = await new Promise<string>((resolve, reject) => {
    bcrypt.hash(
      msg.password,
      salt,
      (err, result) => {
        if (err || !result) reject(err ?? new Error('Key schedule failed'));
        else resolve(result);
      },
      (pct: number) => {
        // `pct` is completedRounds / totalRounds, measured inside the loop.
        reply({
          id: msg.id,
          ok: true,
          progress: {
            round: Math.round(pct * totalRounds),
            totalRounds,
            elapsedMs: performance.now() - t0,
          },
        });
      },
    );
  });

  reply({ id: msg.id, ok: true, result: hash, timeMs: performance.now() - t0 });
}

/**
 * A REAL dictionary attack. Every attempt is a genuine `bcrypt.compareSync`
 * against a genuine stored hash — no timers, no interpolation.
 *
 * Candidates are tried round-robin across targets (word 1 against every user,
 * then word 2, …) because each user has a unique salt: the attacker cannot
 * amortise a guess across the database, which is the whole point of salting.
 *
 * The run stops when `budgetMs` of real CPU time is spent or the list is
 * exhausted. The reported attempt count is what actually executed.
 */
function runCrack(msg: {
  id: number;
  targets: { username: string; hash: string }[];
  candidates: string[];
  budgetMs: number;
}): void {
  const t0 = performance.now();
  const cracked: { username: string; password: string; position: number }[] = [];
  const solved = new Set<string>();
  let attempts = 0;
  let lastPost = t0;
  let exhausted = true;

  outer:
  for (let i = 0; i < msg.candidates.length; i++) {
    const candidate = msg.candidates[i];
    for (const target of msg.targets) {
      if (solved.has(target.username)) continue;
      if (performance.now() - t0 >= msg.budgetMs) { exhausted = false; break outer; }

      attempts++;
      if (bcrypt.compareSync(candidate, target.hash)) {
        solved.add(target.username);
        cracked.push({ username: target.username, password: candidate, position: i + 1 });
      }

      const now = performance.now();
      if (now - lastPost >= 120) {
        lastPost = now;
        reply({
          id: msg.id,
          ok: true,
          progress: {
            attempts,
            wordsTried: i + 1,
            elapsedMs: now - t0,
            cracked: cracked.length,
          },
        });
      }
    }
    if (solved.size === msg.targets.length) { exhausted = true; break; }
  }

  const elapsedMs = performance.now() - t0;
  reply({
    id: msg.id,
    ok: true,
    result: { cracked, attempts, exhausted, msPerAttempt: attempts > 0 ? elapsedMs / attempts : 0 },
    timeMs: elapsedMs,
  });
}
