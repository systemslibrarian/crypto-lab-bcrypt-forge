/**
 * crypto-client.ts — A thin, promise-based RPC wrapper over crypto-worker.ts.
 *
 * The worker is created lazily on first use and reused for the page's
 * lifetime. Every call returns a promise that resolves with the operation's
 * result and the time it took *inside the worker* (so timings reflect the raw
 * primitive, not scheduling overhead).
 */

interface WorkerReply {
  id: number;
  ok: boolean;
  result?: unknown;
  timeMs?: number;
  error?: string;
}

interface Pending {
  resolve: (value: { result: unknown; timeMs: number }) => void;
  reject: (reason: Error) => void;
}

let worker: Worker | null = null;
let seq = 0;
const pending = new Map<number, Pending>();

function getWorker(): Worker {
  if (worker) return worker;
  worker = new Worker(new URL('./crypto-worker.ts', import.meta.url), { type: 'module' });
  worker.onmessage = (e: MessageEvent<WorkerReply>) => {
    const { id, ok, result, timeMs, error } = e.data;
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    if (ok) p.resolve({ result, timeMs: timeMs ?? 0 });
    else p.reject(new Error(error ?? 'Worker error'));
  };
  worker.onerror = (e) => {
    // Fail every outstanding request rather than hanging forever.
    const err = new Error(e.message || 'Crypto worker crashed');
    pending.forEach(p => p.reject(err));
    pending.clear();
  };
  return worker;
}

function call(msg: Record<string, unknown>): Promise<{ result: unknown; timeMs: number }> {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    getWorker().postMessage({ ...msg, id });
  });
}

export const cryptoClient = {
  /** Generate a salt at `cost` and hash `password`. Returns the hash + timing. */
  async hash(password: string, cost: number): Promise<{ hash: string; timeMs: number }> {
    const { result, timeMs } = await call({ op: 'hash', password, cost });
    return { hash: result as string, timeMs };
  },

  /** Constant-time verify of `password` against a stored bcrypt `hash`. */
  async compare(password: string, hash: string): Promise<{ match: boolean; timeMs: number }> {
    const { result, timeMs } = await call({ op: 'compare', password, hash });
    return { match: result as boolean, timeMs };
  },

  /** Compute an (insecure, educational) MD5 digest of `text`. */
  async md5(text: string): Promise<string> {
    const { result } = await call({ op: 'md5', text });
    return result as string;
  },

  /** Derive 256 bits with PBKDF2-HMAC-SHA256. Returns the timing only. */
  async pbkdf2(password: string, iterations: number): Promise<{ timeMs: number }> {
    const { timeMs } = await call({ op: 'pbkdf2', password, iterations });
    return { timeMs };
  },
};
