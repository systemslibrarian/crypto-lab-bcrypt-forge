/**
 * exhibits.ts — All six interactive bcrypt exhibits.
 *
 * Every CPU-heavy operation (bcrypt hashing/verifying, MD5, PBKDF2) is
 * delegated to a Web Worker via `cryptoClient`, so the main thread — and the
 * UI — stays responsive throughout. Hashes are real, never simulated.
 */

import { cryptoClient } from './crypto-client.ts';
import { parseBcryptHash, isBcryptHash, formatDuration, variance } from './lib.ts';

// ─── Helpers ──────────────────────────────────────────────────────

function $(id: string): HTMLElement | null {
  return document.getElementById(id);
}

function escapeHtml(str: string): string {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

/** Color-annotate a bcrypt hash into its four parts. */
function annotateBcryptHash(hash: string): string {
  const parts = parseBcryptHash(hash);
  if (!parts) return escapeHtml(hash);
  return (
    `<span class="anatomy-version">${escapeHtml(parts.version)}</span>` +
    `<span class="anatomy-cost">${escapeHtml(parts.cost)}</span>` +
    `<span class="anatomy-salt">${escapeHtml(parts.salt)}</span>` +
    `<span class="anatomy-hash">${escapeHtml(parts.hash)}</span>`
  );
}

/** Copy text to clipboard, with a graceful fallback for older browsers. */
async function copyToClipboard(text: string, btn: HTMLButtonElement): Promise<void> {
  const flash = () => {
    const orig = btn.dataset.label ?? btn.textContent ?? 'Copy';
    btn.dataset.label = orig;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = btn.dataset.label ?? orig; }, 1500);
  };
  try {
    await navigator.clipboard.writeText(text);
    flash();
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch { /* nothing more we can do */ }
    document.body.removeChild(ta);
    flash();
  }
}

/** Toggle a password input's visibility and keep the button label in sync. */
function wirePasswordToggle(input: HTMLInputElement, toggle: HTMLButtonElement | null): void {
  if (!toggle) return;
  toggle.addEventListener('click', () => {
    const hidden = input.type === 'password';
    input.type = hidden ? 'text' : 'password';
    toggle.textContent = hidden ? '🙈' : '👁';
    toggle.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password');
    toggle.setAttribute('aria-pressed', hidden ? 'true' : 'false');
  });
}

// Store benchmark results for cross-exhibit use (Exhibit 6 uses Exhibit 3 data)
let benchmarkResults: { cost: number; timeMs: number }[] = [];

// ═══════════════════════════════════════════════════════════════════
// EXHIBIT 1 — What bcrypt actually is
// ═══════════════════════════════════════════════════════════════════

export function initExhibit1(): void {
  const display = $('p1-anatomy-display');
  const legend = $('p1-anatomy-legend');
  const arrows = $('p1-anatomy-arrows');
  if (!display || !legend || !arrows) return;

  display.innerHTML = '<span class="spinner"></span> Generating a real bcrypt hash…';

  cryptoClient.hash('ExamplePassword123', 12).then(({ hash }) => {
    display.innerHTML = annotateBcryptHash(hash);

    legend.innerHTML = [
      { cls: 'version', label: 'Version ($2b$)' },
      { cls: 'cost', label: 'Cost factor' },
      { cls: 'salt', label: 'Salt (22 chars)' },
      { cls: 'hash', label: 'Hash (31 chars)' },
    ].map(item =>
      `<div class="anatomy-legend__item" role="listitem">` +
      `<span class="anatomy-legend__dot" style="background: var(--color-${item.cls})"></span>` +
      `<span>${item.label}</span></div>`,
    ).join('');

    arrows.innerHTML =
      '<span style="color:var(--color-version)"> ↑  </span>' +
      '<span style="color:var(--color-cost)"> ↑ </span>' +
      '<span style="color:var(--color-salt)">←———— 22 chars ————→</span>' +
      '<span style="color:var(--color-hash)">←————————— 31 chars —————————→</span>';
  });
}

// ═══════════════════════════════════════════════════════════════════
// EXHIBIT 2 — Hash Generator
// ═══════════════════════════════════════════════════════════════════

export function initExhibit2(): void {
  const passwordInput = $('p2-password') as HTMLInputElement | null;
  const passwordToggle = $('p2-password-toggle') as HTMLButtonElement | null;
  const costSlider = $('p2-cost') as HTMLInputElement | null;
  const costValue = $('p2-cost-value');
  const timingEstimate = $('p2-timing-estimate');
  const hashBtn = $('p2-hash-btn') as HTMLButtonElement | null;
  const resultEl = $('p2-result');
  const timingEl = $('p2-timing');
  const costBarEl = $('p2-cost-bar');

  if (!passwordInput || !costSlider || !hashBtn || !resultEl) return;

  wirePasswordToggle(passwordInput, passwordToggle);

  const estimateTimes: Record<number, string> = {
    4: '~1 ms', 5: '~2 ms', 6: '~4 ms', 7: '~8 ms',
    8: '~15 ms', 9: '~30 ms', 10: '~60 ms', 11: '~120 ms',
    12: '~250 ms', 13: '~500 ms', 14: '~1 s',
  };

  costSlider.addEventListener('input', () => {
    const cost = parseInt(costSlider.value, 10);
    if (costValue) costValue.textContent = String(cost);
    costSlider.setAttribute('aria-valuenow', String(cost));
    if (timingEstimate) {
      timingEstimate.textContent = `Estimated time: ${estimateTimes[cost] ?? '~???'}`;
    }
  });

  hashBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    const cost = parseInt(costSlider.value, 10);

    if (!password) {
      resultEl.innerHTML = '<span style="color: var(--color-invalid-text)">Please enter a password.</span>';
      return;
    }

    hashBtn.disabled = true;
    hashBtn.innerHTML = '<span class="spinner"></span> Hashing…';
    resultEl.innerHTML = '<span class="spinner"></span> Computing bcrypt hash…';
    if (timingEl) timingEl.textContent = '';

    try {
      const { hash, timeMs } = await cryptoClient.hash(password, cost);

      resultEl.innerHTML =
        `<button class="copy-btn" id="p2-copy-btn" type="button" aria-label="Copy hash to clipboard">Copy</button>` +
        annotateBcryptHash(hash);

      const copyBtn = $('p2-copy-btn') as HTMLButtonElement | null;
      if (copyBtn) copyBtn.addEventListener('click', () => copyToClipboard(hash, copyBtn));

      if (timingEl) timingEl.textContent = `Computed in ${timeMs.toFixed(1)} ms`;

      if (costBarEl) {
        const ratio = 2 ** (cost - 10);
        const barWidth = Math.min(100, Math.max(3, ratio * 20));
        const ratioLabel = ratio >= 1 ? `${ratio}×` : `1/${Math.round(1 / ratio)}×`;
        costBarEl.innerHTML =
          `<div style="font-size: 0.8125rem; color: var(--color-text-3); margin-bottom: var(--space-1);">` +
          `Relative to cost 10 (baseline): <strong style="color: var(--color-text);">${ratioLabel}</strong></div>` +
          `<div class="bar-track"><div class="bar-fill ${cost < 10 ? 'bar-fill--danger' : 'bar-fill--safe'}" ` +
          `style="width: ${barWidth}%"></div></div>`;
      }
    } catch (err) {
      resultEl.innerHTML =
        `<span style="color: var(--color-invalid-text)">Hashing failed: ${escapeHtml(String(err))}</span>`;
    } finally {
      hashBtn.disabled = false;
      hashBtn.textContent = 'Hash It';
    }
  });
}

// ═══════════════════════════════════════════════════════════════════
// EXHIBIT 3 — Cost Factor Timing Benchmark
// ═══════════════════════════════════════════════════════════════════

export function initExhibit3(): void {
  const runBtn = $('p3-run-btn') as HTMLButtonElement | null;
  const statusEl = $('p3-status');
  const chartEl = $('p3-chart');
  const crackingEl = $('p3-cracking-estimates');

  if (!runBtn || !chartEl) return;

  runBtn.addEventListener('click', async () => {
    runBtn.disabled = true;
    runBtn.innerHTML = '<span class="spinner"></span> Running…';
    chartEl.innerHTML = '';
    if (crackingEl) crackingEl.innerHTML = '';

    benchmarkResults = [];
    const password = 'BenchmarkPassword2024!';
    const results: { cost: number; timeMs: number }[] = [];
    let baseTime = 0;

    for (let cost = 8; cost <= 14; cost++) {
      if (statusEl) statusEl.textContent = `Hashing at cost ${cost}…`;
      const { timeMs } = await cryptoClient.hash(password, cost);
      if (cost === 8) baseTime = timeMs;
      results.push({ cost, timeMs });
    }

    benchmarkResults = results;
    const maxTime = Math.max(...results.map(r => r.timeMs));

    let chartHtml = '<div class="zone-label zone-label--danger">⚠ Danger zone (cost &lt; 10)</div>';
    for (const r of results) {
      const pct = (r.timeMs / maxTime) * 100;
      const multiplier = (r.timeMs / baseTime).toFixed(1);
      const isSafe = r.cost >= 10;
      if (r.cost === 10) {
        chartHtml += '<div class="zone-label zone-label--safe">✓ Safe zone (cost ≥ 10)</div>';
      }
      chartHtml +=
        `<div class="bar-row">` +
        `<span class="bar-label">${r.cost}</span>` +
        `<div class="bar-track"><div class="bar-fill ${isSafe ? 'bar-fill--safe' : 'bar-fill--danger'}" ` +
        `style="width: ${pct}%"></div></div>` +
        `<span class="bar-time">${r.timeMs.toFixed(0)} ms</span>` +
        `<span class="bar-multiplier">${multiplier}×</span>` +
        `</div>`;
    }
    chartEl.innerHTML = chartHtml;

    if (crackingEl) {
      let crackHtml =
        '<div style="margin-top: var(--space-4); padding: var(--space-4); background: var(--color-surface); ' +
        'border: 1px solid var(--color-border); border-radius: var(--radius-md);">' +
        '<div style="font-weight: 700; color: var(--color-text); margin-bottom: var(--space-3);">' +
        'Single-GPU brute-force of one password (8-char lowercase + digit, ~2.8 trillion candidates)</div>';

      // A single high-end GPU does the work you just measured, but massively
      // parallel. Assume ~10,000× your single-thread rate as a rough proxy.
      const gpuParallelism = 10_000;
      for (const r of results) {
        const yourHashesPerSec = 1000 / r.timeMs;
        const attackerHashesPerSec = yourHashesPerSec * gpuParallelism;
        const keyspace = 36 ** 8 / 2; // expected attempts = half the keyspace
        const seconds = keyspace / attackerHashesPerSec;
        crackHtml +=
          `<div style="display: flex; justify-content: space-between; padding: var(--space-1) 0; ` +
          `border-bottom: 1px solid var(--color-border); font-size: 0.8125rem;">` +
          `<span style="color: var(--color-text-2);">Cost ${r.cost}</span>` +
          `<span style="font-family: var(--font-mono); color: ${r.cost >= 10 ? 'var(--color-valid-text)' : 'var(--color-invalid-text)'};">` +
          `${formatDuration(seconds)}</span></div>`;
      }
      crackHtml +=
        '<div style="font-size: 0.75rem; color: var(--color-text-3); margin-top: var(--space-2);">' +
        'Order-of-magnitude estimate. Each +1 in cost doubles every figure above.</div></div>';
      crackingEl.innerHTML = crackHtml;
    }

    if (statusEl) statusEl.textContent = 'Benchmark complete.';
    runBtn.disabled = false;
    runBtn.textContent = 'Run Benchmark';
  });
}

// ═══════════════════════════════════════════════════════════════════
// EXHIBIT 4 — Verify & Timing-Safe Comparison
// ═══════════════════════════════════════════════════════════════════

const EXAMPLE_PASSWORD = 'correcthorsebatterystaple';
let exampleHash = '';

export function initExhibit4(): void {
  const passwordInput = $('p4-password') as HTMLInputElement | null;
  const passwordToggle = $('p4-password-toggle') as HTMLButtonElement | null;
  const hashInput = $('p4-hash') as HTMLInputElement | null;
  const verifyBtn = $('p4-verify-btn') as HTMLButtonElement | null;
  const correctBtn = $('p4-example-correct-btn') as HTMLButtonElement | null;
  const wrongBtn = $('p4-example-wrong-btn') as HTMLButtonElement | null;
  const resultEl = $('p4-verify-result');
  const timingBtn = $('p4-timing-btn') as HTMLButtonElement | null;
  const naiveChart = $('p4-naive-chart');
  const bcryptChart = $('p4-bcrypt-chart');
  const timingStats = $('p4-timing-stats');

  if (!passwordInput || !hashInput || !verifyBtn || !resultEl) return;

  // Generate the example hash off-thread; disable example buttons until ready.
  if (correctBtn) correctBtn.disabled = true;
  if (wrongBtn) wrongBtn.disabled = true;
  cryptoClient.hash(EXAMPLE_PASSWORD, 10).then(({ hash }) => {
    exampleHash = hash;
    if (correctBtn) correctBtn.disabled = false;
    if (wrongBtn) wrongBtn.disabled = false;
  });

  wirePasswordToggle(passwordInput, passwordToggle);

  if (correctBtn) {
    correctBtn.addEventListener('click', () => {
      passwordInput.value = EXAMPLE_PASSWORD;
      hashInput.value = exampleHash;
    });
  }
  if (wrongBtn) {
    wrongBtn.addEventListener('click', () => {
      passwordInput.value = 'wrongpassword';
      hashInput.value = exampleHash;
    });
  }

  verifyBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    const hash = hashInput.value.trim();

    if (!password || !hash) {
      resultEl.innerHTML = '<div class="status-display">Please enter both a password and a hash.</div>';
      return;
    }
    if (!isBcryptHash(hash)) {
      resultEl.innerHTML =
        '<div class="verify-result verify-result--no-match">' +
        '⚠ Invalid bcrypt hash format. Generate one in Exhibit 2 or click "Load Correct Pair".</div>';
      return;
    }

    verifyBtn.disabled = true;
    verifyBtn.innerHTML = '<span class="spinner"></span> Verifying…';

    try {
      const { match, timeMs } = await cryptoClient.compare(password, hash);
      resultEl.innerHTML = match
        ? `<div class="verify-result verify-result--match">✓ Match — verified in ${timeMs.toFixed(1)} ms</div>`
        : `<div class="verify-result verify-result--no-match">✗ No match — checked in ${timeMs.toFixed(1)} ms</div>`;
    } catch (err) {
      resultEl.innerHTML =
        `<div class="verify-result verify-result--no-match">Verify failed: ${escapeHtml(String(err))}</div>`;
    } finally {
      verifyBtn.disabled = false;
      verifyBtn.textContent = 'Verify';
    }
  });

  if (timingBtn && naiveChart && bcryptChart) {
    timingBtn.addEventListener('click', async () => {
      if (!exampleHash) return;
      timingBtn.disabled = true;
      timingBtn.innerHTML = '<span class="spinner"></span> Running…';

      const target = exampleHash;
      const naiveTimings: number[] = [];
      const bcryptTimings: number[] = [];

      // 10 probes that match progressively more of the hash prefix.
      const testStrings: string[] = [];
      for (let i = 0; i < 10; i++) {
        const prefix = target.substring(0, i * 6);
        testStrings.push(prefix + 'x'.repeat(target.length - prefix.length));
      }

      for (let i = 0; i < 10; i++) {
        // Naive ===: an *illustrative* byte-by-byte compare whose duration
        // grows with the matching-prefix length — the leak constant-time
        // comparison is designed to prevent.
        const testStr = testStrings[i];
        const t0 = performance.now();
        for (let j = 0; j < testStr.length; j++) {
          if (testStr[j] !== target[j]) break;
          const end = performance.now() + 0.005;
          while (performance.now() < end) { /* busy wait — exaggerate the leak */ }
        }
        naiveTimings.push(performance.now() - t0);

        // bcrypt compare runs off-thread and is timed inside the worker.
        const { timeMs } = await cryptoClient.compare(EXAMPLE_PASSWORD, target);
        bcryptTimings.push(timeMs);
      }

      const globalMaxNaive = Math.max(...naiveTimings, 0.01);
      const globalMaxBcrypt = Math.max(...bcryptTimings, 0.01);

      naiveChart.innerHTML = naiveTimings.map((t, i) =>
        `<div class="timing-row">` +
        `<span class="timing-label">#${i + 1}</span>` +
        `<div class="bar-track" style="height: 16px;">` +
        `<div class="timing-bar timing-bar--naive" style="width: ${(t / globalMaxNaive) * 100}%"></div></div>` +
        `<span class="timing-label">${t.toFixed(3)}ms</span></div>`,
      ).join('');

      bcryptChart.innerHTML = bcryptTimings.map((t, i) =>
        `<div class="timing-row">` +
        `<span class="timing-label">#${i + 1}</span>` +
        `<div class="bar-track" style="height: 16px;">` +
        `<div class="timing-bar timing-bar--bcrypt" style="width: ${(t / globalMaxBcrypt) * 100}%"></div></div>` +
        `<span class="timing-label">${t.toFixed(1)}ms</span></div>`,
      ).join('');

      if (timingStats) {
        timingStats.innerHTML =
          `<div class="status-display">` +
          `<strong>Timing variance:</strong> ` +
          `Naive: <span style="color: var(--color-invalid-text);">${variance(naiveTimings).toFixed(4)} ms²</span> — ` +
          `bcrypt: <span style="color: var(--color-valid-text);">${variance(bcryptTimings).toFixed(4)} ms²</span><br>` +
          `<span style="font-size: 0.8125rem; color: var(--color-text-3);">` +
          `The naive bars are an exaggerated illustration; the leak is real but measured in nanoseconds. ` +
          `bcrypt's constant-time compare reveals nothing about where a mismatch occurs.</span></div>`;
      }

      timingBtn.disabled = false;
      timingBtn.textContent = 'Run Timing Comparison';
    });
  }
}

// ═══════════════════════════════════════════════════════════════════
// EXHIBIT 5 — bcrypt vs Alternatives
// ═══════════════════════════════════════════════════════════════════

interface AlgorithmRow {
  name: string;
  year: number;
  adaptive: boolean;
  memoryHard: boolean | 'Partial';
  gpuResistant: boolean | 'Partial';
  status: string;
  statusClass: string;
  description: string;
}

const algorithms: AlgorithmRow[] = [
  {
    name: 'MD5 (raw)', year: 1992, adaptive: false, memoryHard: false, gpuResistant: false,
    status: '❌ Never use', statusClass: 'color: var(--color-invalid-text)',
    description: 'MD5 was designed for speed, not security. A modern GPU can compute billions of MD5 hashes per second. Rainbow tables for MD5 are freely available and cover most common passwords.',
  },
  {
    name: 'SHA-256 (raw)', year: 2001, adaptive: false, memoryHard: false, gpuResistant: false,
    status: '❌ Never use', statusClass: 'color: var(--color-invalid-text)',
    description: 'SHA-256 is a secure hash function for data integrity, but it is far too fast for password hashing. Without a cost factor or salt, brute-force attacks are trivial at scale.',
  },
  {
    name: 'PBKDF2', year: 2000, adaptive: true, memoryHard: false, gpuResistant: false,
    status: '⚠️ FIPS only', statusClass: 'color: var(--color-warning-text)',
    description: 'PBKDF2 applies a PRF (typically HMAC-SHA256) iteratively. It is NIST-approved and required in FIPS environments. However, it is not memory-hard, making it vulnerable to GPU and ASIC attacks.',
  },
  {
    name: 'bcrypt', year: 1999, adaptive: true, memoryHard: 'Partial', gpuResistant: 'Partial',
    status: '✅ Recommended', statusClass: 'color: var(--color-valid-text)',
    description: 'bcrypt uses the Blowfish cipher\'s expensive key setup to make each hash computation deliberately slow. Its 4 KB internal state provides partial memory-hardness, making GPU parallelization harder than raw SHA or PBKDF2.',
  },
  {
    name: 'scrypt', year: 2009, adaptive: true, memoryHard: true, gpuResistant: true,
    status: '✅ Recommended', statusClass: 'color: var(--color-valid-text)',
    description: 'scrypt uses a large memory buffer (configurable) that makes hardware-parallelized attacks expensive. Originally designed for key derivation, it is also suitable for password hashing when properly tuned.',
  },
  {
    name: 'Argon2id', year: 2015, adaptive: true, memoryHard: true, gpuResistant: true,
    status: '✅ Preferred (NIST)', statusClass: 'color: var(--color-valid-text)',
    description: 'Argon2id (winner of the Password Hashing Competition, 2015) combines Argon2i\'s side-channel resistance with Argon2d\'s GPU resistance. NIST SP 800-63B recommends it as the preferred password hashing algorithm for new systems.',
  },
];

export function initExhibit5(): void {
  const tbody = $('p5-table-body');
  const raceBtn = $('p5-race-btn') as HTMLButtonElement | null;
  const raceResult = $('p5-race-result');

  if (!tbody) return;

  const bool = (v: boolean | 'Partial') =>
    v === true ? '✓' : v === 'Partial' ? 'Partial' : '✗';

  let html = '';
  for (const algo of algorithms) {
    html +=
      `<tr data-expandable data-algo="${escapeHtml(algo.name)}" ` +
      `role="button" tabindex="0" aria-expanded="false" ` +
      `aria-label="${escapeHtml(algo.name)} — activate to expand details">` +
      `<td style="text-align: left; font-weight: 600;"><span class="expand-icon" aria-hidden="true">▶</span> ${escapeHtml(algo.name)}</td>` +
      `<td>${algo.year}</td>` +
      `<td>${bool(algo.adaptive)}</td>` +
      `<td>${bool(algo.memoryHard)}</td>` +
      `<td>${bool(algo.gpuResistant)}</td>` +
      `<td style="${algo.statusClass}">${algo.status}</td>` +
      `</tr>` +
      `<tr class="expand-row" hidden>` +
      `<td colspan="6">${escapeHtml(algo.description)}</td>` +
      `</tr>`;
  }
  tbody.innerHTML = html;

  tbody.querySelectorAll<HTMLTableRowElement>('[data-expandable]').forEach(row => {
    const handler = () => {
      const expandRow = row.nextElementSibling as HTMLTableRowElement | null;
      if (!expandRow) return;
      const isOpen = !expandRow.hidden;
      expandRow.hidden = isOpen;
      row.setAttribute('aria-expanded', String(!isOpen));
      row.querySelector('.expand-icon')?.classList.toggle('expand-icon--open', !isOpen);
    };
    row.addEventListener('click', handler);
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handler();
      }
    });
  });

  if (raceBtn && raceResult) {
    raceBtn.addEventListener('click', async () => {
      raceBtn.disabled = true;
      raceBtn.innerHTML = '<span class="spinner"></span> Running…';
      raceResult.innerHTML = '<span class="spinner"></span> Hashing with bcrypt (cost 12)…';

      try {
        const { timeMs: bcryptTime } = await cryptoClient.hash('TimingComparisonTest', 12);

        raceResult.innerHTML = '<span class="spinner"></span> Deriving with PBKDF2 (100k rounds)…';
        const { timeMs: pbkdf2Time } = await cryptoClient.pbkdf2('TimingComparisonTest', 100_000);

        raceResult.innerHTML =
          `<div class="status-display">` +
          `<div style="display: flex; justify-content: space-between; margin-bottom: var(--space-2);">` +
          `<span style="font-weight: 700;">bcrypt (cost 12):</span>` +
          `<span style="font-family: var(--font-mono); color: var(--color-primary);">${bcryptTime.toFixed(1)} ms</span></div>` +
          `<div style="display: flex; justify-content: space-between;">` +
          `<span style="font-weight: 700;">PBKDF2 (100k rounds):</span>` +
          `<span style="font-family: var(--font-mono); color: var(--color-warning-text);">${pbkdf2Time.toFixed(1)} ms</span></div>` +
          `</div>`;
      } catch (err) {
        raceResult.innerHTML = `<div class="status-display">Comparison failed: ${escapeHtml(String(err))}</div>`;
      } finally {
        raceBtn.disabled = false;
        raceBtn.textContent = 'Run Comparison';
      }
    });
  }
}

// ═══════════════════════════════════════════════════════════════════
// EXHIBIT 6 — Real-World Attack Demo
// ═══════════════════════════════════════════════════════════════════

interface DemoUser {
  username: string;
  password: string;
}

const DEMO_USERS: DemoUser[] = [
  { username: 'alice', password: 'password123' },
  { username: 'bob', password: 'letmein' },
  { username: 'carol', password: 'qwerty' },
  { username: 'dave', password: '123456' },
  { username: 'eve', password: 'password123' },  // same as alice — shows duplicate hash issue
  { username: 'frank', password: 'dragon' },
  { username: 'grace', password: 'iloveyou' },
  { username: 'heidi', password: 'monkey' },
];

export function initExhibit6(): void {
  const aContainer = $('p6a-table-container');
  const bContainer = $('p6b-table-container');
  const cContainer = $('p6c-table-container');
  const aBreachBtn = $('p6a-breach-btn') as HTMLButtonElement | null;
  const bBreachBtn = $('p6b-breach-btn') as HTMLButtonElement | null;
  const cBreachBtn = $('p6c-breach-btn') as HTMLButtonElement | null;

  if (!aContainer || !bContainer || !cContainer) return;

  initScenarioA(aContainer, aBreachBtn);
  initScenarioB(bContainer, bBreachBtn);
  initScenarioC(cContainer, cBreachBtn);
}

function initScenarioA(container: HTMLElement, breachBtn: HTMLButtonElement | null): void {
  let html = '<div class="table-scroll" tabindex="0" role="region" aria-label="Plaintext password database (scrollable)">' +
    '<table class="user-table" aria-label="Plaintext storage database">' +
    '<thead><tr><th scope="col">User</th><th scope="col">Stored Password</th></tr></thead><tbody>';
  for (const u of DEMO_USERS) {
    html += `<tr><td>${escapeHtml(u.username)}</td>` +
      `<td class="p6a-pw" data-pw="${escapeHtml(u.password)}">••••••••</td></tr>`;
  }
  html += '</tbody></table></div>';
  container.innerHTML = html;

  if (breachBtn) {
    breachBtn.addEventListener('click', () => {
      container.querySelectorAll<HTMLElement>('.p6a-pw').forEach(cell => {
        cell.textContent = cell.dataset.pw ?? '';
        cell.classList.add('revealed');
      });
      breachBtn.disabled = true;
      breachBtn.textContent = 'Breached!';
      const callout = $('p6a-callout');
      if (callout) callout.style.display = '';
    });
  }
}

async function initScenarioB(container: HTMLElement, breachBtn: HTMLButtonElement | null): Promise<void> {
  const usersWithMd5 = await Promise.all(
    DEMO_USERS.map(async u => ({ ...u, md5Hash: await cryptoClient.md5(u.password) })),
  );

  let html = '<div class="table-scroll" tabindex="0" role="region" aria-label="MD5 hash database (scrollable)">' +
    '<table class="user-table" aria-label="MD5 hash storage database">' +
    '<thead><tr><th scope="col">User</th><th scope="col">MD5 Hash</th><th scope="col">Cracked?</th></tr></thead><tbody>';
  for (const u of usersWithMd5) {
    html += `<tr><td>${escapeHtml(u.username)}</td>` +
      `<td>${escapeHtml(u.md5Hash)}</td>` +
      `<td class="p6b-crack" data-pw="${escapeHtml(u.password)}">—</td></tr>`;
  }
  html += '</tbody></table></div>';
  container.innerHTML = html;

  const hashCounts = new Map<string, number>();
  usersWithMd5.forEach(u => hashCounts.set(u.md5Hash, (hashCounts.get(u.md5Hash) ?? 0) + 1));
  const duplicates = [...hashCounts.values()].filter(c => c > 1);
  if (duplicates.length > 0) {
    container.insertAdjacentHTML('beforeend',
      `<div style="font-size: 0.8125rem; color: var(--color-warning-text); margin-top: var(--space-2);">` +
      `⚠ Notice: ${duplicates.length} hash(es) appear more than once — identical passwords produce identical unsalted hashes.</div>`);
  }

  if (breachBtn) {
    breachBtn.addEventListener('click', async () => {
      breachBtn.disabled = true;
      breachBtn.innerHTML = '<span class="spinner"></span> Looking up…';

      const cells = container.querySelectorAll<HTMLElement>('.p6b-crack');
      for (const cell of cells) {
        await new Promise(r => setTimeout(r, 180));
        cell.textContent = cell.dataset.pw ?? '';
        cell.classList.add('revealed');
      }

      breachBtn.textContent = 'All Cracked!';
      const callout = $('p6b-callout');
      if (callout) callout.style.display = '';
    });
  }
}

async function initScenarioC(container: HTMLElement, breachBtn: HTMLButtonElement | null): Promise<void> {
  // Render the table immediately with placeholders, then fill each hash in as
  // the worker produces it — the visible drip-feed *is* the lesson: cost-12
  // bcrypt is slow even to generate.
  let html = '<div class="table-scroll" tabindex="0" role="region" aria-label="bcrypt hash database (scrollable)">' +
    '<table class="user-table" aria-label="bcrypt hash storage database">' +
    '<thead><tr><th scope="col">User</th><th scope="col">bcrypt Hash</th><th scope="col">Cracked?</th></tr></thead><tbody>';
  for (const u of DEMO_USERS) {
    html += `<tr><td>${escapeHtml(u.username)}</td>` +
      `<td class="p6c-hash" id="p6c-hash-${escapeHtml(u.username)}"><span class="spinner"></span> hashing…</td>` +
      `<td class="p6c-crack safe">Protected</td></tr>`;
  }
  html += '</tbody></table></div>';
  container.innerHTML = html;

  for (const u of DEMO_USERS) {
    const { hash } = await cryptoClient.hash(u.password, 12);
    const cell = $(`p6c-hash-${u.username}`);
    if (cell) cell.textContent = hash;
  }

  container.insertAdjacentHTML('beforeend',
    `<div style="font-size: 0.8125rem; color: var(--color-valid-text); margin-top: var(--space-2);">` +
    `✓ Notice: alice and eve share the same password, but their bcrypt hashes are completely different — each gets a unique salt.</div>`);

  if (breachBtn) {
    breachBtn.addEventListener('click', () => {
      breachBtn.disabled = true;
      breachBtn.innerHTML = '<span class="spinner"></span> Cracking…';

      const progressEl = $('p6c-progress');
      const fillEl = $('p6c-progress-fill');
      const textEl = $('p6c-progress-text');
      if (progressEl) progressEl.style.display = '';

      const timePerHash = benchmarkResults.find(r => r.cost === 12)?.timeMs ?? 250;
      const dictionarySize = 100_000;
      const totalSeconds = (dictionarySize * timePerHash) / 1000;
      const timeStr = formatDuration(totalSeconds);

      let elapsedMs = 0;
      const totalMs = totalSeconds * 1000;
      const interval = window.setInterval(() => {
        elapsedMs += 100;
        const progress = Math.min((elapsedMs / totalMs) * 100, 100);
        if (fillEl) (fillEl as HTMLElement).style.width = `${progress}%`;
        if (textEl) {
          textEl.textContent =
            `Attempted ${Math.floor(dictionarySize * progress / 100).toLocaleString()} of ` +
            `${dictionarySize.toLocaleString()} dictionary words… Estimated total: ${timeStr} per user`;
        }
        if (progress >= 100) clearInterval(interval);
      }, 100);

      window.setTimeout(() => {
        clearInterval(interval);
        if (textEl) {
          textEl.innerHTML =
            `<strong style="color: var(--color-valid-text);">Gave up after 5 seconds.</strong> ` +
            `At ${timePerHash.toFixed(0)} ms/hash, cracking a 100,000-word dictionary would take ` +
            `<strong>${timeStr}</strong> per user × ${DEMO_USERS.length} users.`;
        }
        breachBtn.textContent = 'Too Slow!';
        const callout = $('p6c-callout');
        if (callout) callout.style.display = '';
      }, 5000);
    });
  }
}
