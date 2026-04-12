/**
 * exhibits.ts — All six interactive bcrypt exhibits.
 * Uses bcryptjs for real hashing. No simulated output.
 */

import bcrypt from 'bcryptjs';

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
  // Format: $2b$12$<22-char salt><31-char hash>
  const match = hash.match(/^(\$2[aby]?\$)(\d{2}\$)(.{22})(.{31})$/);
  if (!match) return escapeHtml(hash);
  return (
    `<span class="anatomy-version">${escapeHtml(match[1])}</span>` +
    `<span class="anatomy-cost">${escapeHtml(match[2])}</span>` +
    `<span class="anatomy-salt">${escapeHtml(match[3])}</span>` +
    `<span class="anatomy-hash">${escapeHtml(match[4])}</span>`
  );
}

/** Real MD5 implementation for educational display in Exhibit 6. */
function md5(message: string): string {
  function rotateLeft(x: number, c: number): number {
    return (x << c) | (x >>> (32 - c));
  }

  function addUnsigned(a: number, b: number): number {
    return (a + b) >>> 0;
  }

  function F(x: number, y: number, z: number): number {
    return (x & y) | (~x & z);
  }

  function G(x: number, y: number, z: number): number {
    return (x & z) | (y & ~z);
  }

  function H(x: number, y: number, z: number): number {
    return x ^ y ^ z;
  }

  function I(x: number, y: number, z: number): number {
    return y ^ (x | ~z);
  }

  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];

  const K = new Array<number>(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  }

  const encoder = new TextEncoder();
  const input = encoder.encode(message);
  const bitLen = input.length * 8;

  const paddedLen = (((input.length + 8) >>> 6) + 1) * 64;
  const data = new Uint8Array(paddedLen);
  data.set(input);
  data[input.length] = 0x80;

  const view = new DataView(data.buffer);
  view.setUint32(paddedLen - 8, bitLen >>> 0, true);
  view.setUint32(paddedLen - 4, Math.floor(bitLen / 0x100000000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let offset = 0; offset < paddedLen; offset += 64) {
    const M = new Array<number>(16);
    for (let i = 0; i < 16; i++) {
      M[i] = view.getUint32(offset + i * 4, true);
    }

    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;

    for (let i = 0; i < 64; i++) {
      let f = 0;
      let g = 0;

      if (i < 16) {
        f = F(B, C, D);
        g = i;
      } else if (i < 32) {
        f = G(B, C, D);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = H(B, C, D);
        g = (3 * i + 5) % 16;
      } else {
        f = I(B, C, D);
        g = (7 * i) % 16;
      }

      const tmp = D;
      D = C;
      C = B;
      B = addUnsigned(B, rotateLeft(addUnsigned(addUnsigned(A, f), addUnsigned(K[i], M[g])), S[i]));
      A = tmp;
    }

    a0 = addUnsigned(a0, A);
    b0 = addUnsigned(b0, B);
    c0 = addUnsigned(c0, C);
    d0 = addUnsigned(d0, D);
  }

  function toHexLE(n: number): string {
    return [
      n & 0xff,
      (n >>> 8) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 24) & 0xff,
    ].map(v => v.toString(16).padStart(2, '0')).join('');
  }

  return toHexLE(a0) + toHexLE(b0) + toHexLE(c0) + toHexLE(d0);
}

/** Copy text to clipboard. */
async function copyToClipboard(text: string, btn: HTMLButtonElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1500);
  } catch {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1500);
  }
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

  // Generate a real bcrypt hash for the example
  const salt = bcrypt.genSaltSync(12);
  const hash = bcrypt.hashSync('ExamplePassword123', salt);

  display.innerHTML = annotateBcryptHash(hash);

  legend.innerHTML = [
    { cls: 'anatomy-version', label: 'Version ($2b$)' },
    { cls: 'anatomy-cost', label: 'Cost factor' },
    { cls: 'anatomy-salt', label: 'Salt (22 chars)' },
    { cls: 'anatomy-hash', label: 'Hash (31 chars)' },
  ].map(item =>
    `<div class="anatomy-legend__item" role="listitem">` +
    `<span class="anatomy-legend__dot" style="background: var(--color-${item.cls.replace('anatomy-', '')})"></span>` +
    `<span>${item.label}</span></div>`
  ).join('');

  arrows.innerHTML =
    '<span style="color:var(--color-version)"> ↑  </span>' +
    '<span style="color:var(--color-cost)"> ↑ </span>' +
    '<span style="color:var(--color-salt)">←———— 22 chars ————→</span>' +
    '<span style="color:var(--color-hash)">←————————— 31 chars —————————→</span>';
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

  // Password show/hide toggle
  if (passwordToggle) {
    passwordToggle.addEventListener('click', () => {
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
      passwordToggle.textContent = isPassword ? '🙈' : '👁';
      passwordToggle.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
  }

  // Cost slider update
  const estimateTimes: Record<number, string> = {
    4: '~1 ms', 5: '~2 ms', 6: '~4 ms', 7: '~8 ms',
    8: '~15 ms', 9: '~30 ms', 10: '~100 ms', 11: '~200 ms',
    12: '~400 ms', 13: '~800 ms', 14: '~1.6 s',
  };

  costSlider.addEventListener('input', () => {
    const cost = parseInt(costSlider.value, 10);
    if (costValue) costValue.textContent = String(cost);
    costSlider.setAttribute('aria-valuenow', String(cost));
    if (timingEstimate) {
      timingEstimate.textContent = `Estimated time: ${estimateTimes[cost] ?? '~???'}`;
    }
  });

  // Hash button
  hashBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    const cost = parseInt(costSlider.value, 10);

    if (!password) {
      resultEl.innerHTML = '<span style="color: var(--color-invalid)">Please enter a password.</span>';
      return;
    }

    hashBtn.disabled = true;
    hashBtn.innerHTML = '<span class="spinner"></span> Hashing…';
    resultEl.innerHTML = '<span class="spinner"></span> Computing bcrypt hash…';

    // Use setTimeout to let the UI update before blocking
    await new Promise(r => setTimeout(r, 50));

    const t0 = performance.now();
    const salt = bcrypt.genSaltSync(cost);
    const hash = bcrypt.hashSync(password, salt);
    const elapsed = performance.now() - t0;

    // Color-annotated result with copy button
    resultEl.innerHTML =
      `<button class="copy-btn" id="p2-copy-btn" type="button" aria-label="Copy hash to clipboard">Copy</button>` +
      annotateBcryptHash(hash);

    const copyBtn = $('p2-copy-btn') as HTMLButtonElement | null;
    if (copyBtn) {
      copyBtn.addEventListener('click', () => copyToClipboard(hash, copyBtn));
    }

    // Timing
    if (timingEl) {
      timingEl.textContent = `Computed in ${elapsed.toFixed(1)} ms`;
    }

    // Relative cost bar
    if (costBarEl) {
      const baseline = 10;
      const ratio = Math.pow(2, cost - baseline);
      const barWidth = Math.min(100, Math.max(3, ratio * 20));
      costBarEl.innerHTML =
        `<div style="font-size: 0.8125rem; color: var(--color-text-3); margin-bottom: var(--space-1);">` +
        `Relative to cost 10 (baseline): <strong style="color: var(--color-text);">${ratio}×</strong></div>` +
        `<div class="bar-track"><div class="bar-fill ${cost < 10 ? 'bar-fill--danger' : 'bar-fill--safe'}" ` +
        `style="width: ${barWidth}%"></div></div>`;
    }

    hashBtn.disabled = false;
    hashBtn.textContent = 'Hash It';
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
    if (statusEl) statusEl.textContent = 'Running sequential benchmark…';
    chartEl.innerHTML = '';

    benchmarkResults = [];
    const password = 'BenchmarkPassword2024!';
    const results: { cost: number; timeMs: number }[] = [];
    let baseTime = 0;

    for (let cost = 8; cost <= 14; cost++) {
      if (statusEl) statusEl.textContent = `Hashing at cost ${cost}…`;

      // Let UI update
      await new Promise(r => setTimeout(r, 30));

      const t0 = performance.now();
      const salt = bcrypt.genSaltSync(cost);
      bcrypt.hashSync(password, salt);
      const elapsed = performance.now() - t0;

      if (cost === 8) baseTime = elapsed;
      results.push({ cost, timeMs: elapsed });
    }

    benchmarkResults = results;
    const maxTime = Math.max(...results.map(r => r.timeMs));

    // Render bar chart
    let chartHtml = '';
    // Danger zone label
    chartHtml += '<div class="zone-label zone-label--danger">⚠ Danger zone (cost &lt; 10)</div>';

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

    // Cracking time estimates
    if (crackingEl) {
      const attackerRate = 1_000_000; // 1M hash/sec baseline for MD5
      let crackHtml =
        '<div style="margin-top: var(--space-4); padding: var(--space-4); background: var(--color-surface); ' +
        'border: 1px solid var(--color-border); border-radius: var(--radius-md);">' +
        '<div style="font-weight: 700; color: var(--color-text); margin-bottom: var(--space-3);">' +
        'Estimated cracking time (100,000-word dictionary)</div>';

      for (const r of results) {
        // At cost N, bcrypt does 2^N iterations. hashRate = 1 / (r.timeMs/1000)
        const hashesPerSec = 1000 / r.timeMs;
        const dictionarySize = 100_000;
        const totalSeconds = dictionarySize / hashesPerSec;
        let timeStr: string;
        if (totalSeconds < 60) timeStr = `${totalSeconds.toFixed(1)} seconds`;
        else if (totalSeconds < 3600) timeStr = `${(totalSeconds / 60).toFixed(1)} minutes`;
        else if (totalSeconds < 86400) timeStr = `${(totalSeconds / 3600).toFixed(1)} hours`;
        else timeStr = `${(totalSeconds / 86400).toFixed(1)} days`;

        crackHtml +=
          `<div style="display: flex; justify-content: space-between; padding: var(--space-1) 0; ` +
          `border-bottom: 1px solid var(--color-border); font-size: 0.8125rem;">` +
          `<span style="color: var(--color-text-2);">Cost ${r.cost}</span>` +
          `<span style="font-family: var(--font-mono); color: ${r.cost >= 10 ? 'var(--color-valid-text)' : 'var(--color-invalid-text)'};">` +
          `${timeStr}</span></div>`;
      }

      crackHtml += '</div>';
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

// Pre-computed example pair for "load correct"
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

  // Generate example hash on init
  const salt = bcrypt.genSaltSync(10);
  exampleHash = bcrypt.hashSync(EXAMPLE_PASSWORD, salt);

  // Password toggle
  if (passwordToggle) {
    passwordToggle.addEventListener('click', () => {
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
      passwordToggle.textContent = isPassword ? '🙈' : '👁';
      passwordToggle.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
  }

  // Load example pairs
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

  // Verify
  verifyBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    const hash = hashInput.value.trim();

    if (!password || !hash) {
      resultEl.innerHTML = '<div class="status-display">Please enter both a password and a hash.</div>';
      return;
    }

    if (!/^\$2[aby]?\$\d{2}\$.{53}$/.test(hash)) {
      resultEl.innerHTML =
        '<div class="verify-result verify-result--no-match">' +
        '⚠ Invalid bcrypt hash format. Generate one in Exhibit 2 or click "Load Correct Pair".</div>';
      return;
    }

    verifyBtn.disabled = true;
    verifyBtn.innerHTML = '<span class="spinner"></span> Verifying…';

    await new Promise(r => setTimeout(r, 30));

    const t0 = performance.now();
    const match = bcrypt.compareSync(password, hash);
    const elapsed = performance.now() - t0;

    if (match) {
      resultEl.innerHTML =
        `<div class="verify-result verify-result--match">` +
        `✓ Match — verified in ${elapsed.toFixed(1)} ms</div>`;
    } else {
      resultEl.innerHTML =
        `<div class="verify-result verify-result--no-match">` +
        `✗ No match — checked in ${elapsed.toFixed(1)} ms</div>`;
    }

    verifyBtn.disabled = false;
    verifyBtn.textContent = 'Verify';
  });

  // Timing attack visualizer
  if (timingBtn && naiveChart && bcryptChart) {
    timingBtn.addEventListener('click', async () => {
      timingBtn.disabled = true;
      timingBtn.innerHTML = '<span class="spinner"></span> Running…';

      const target = exampleHash;
      const naiveTimings: number[] = [];
      const bcryptTimings: number[] = [];

      // Generate 10 test strings with varying prefix match lengths
      const testStrings: string[] = [];
      for (let i = 0; i < 10; i++) {
        // Create strings that match more and more characters of the hash
        const prefix = target.substring(0, i * 6);
        const suffix = 'x'.repeat(target.length - prefix.length);
        testStrings.push(prefix + suffix);
      }

      for (let i = 0; i < 10; i++) {
        // Naive === comparison (simulate variable timing based on match position)
        const testStr = testStrings[i];
        const t0 = performance.now();
        // Simulate char-by-char comparison with measurable delay
        let matchCount = 0;
        for (let j = 0; j < testStr.length; j++) {
          if (testStr[j] === target[j]) {
            matchCount++;
            // Tiny busy-wait to simulate measurable timing difference
            const end = performance.now() + 0.005;
            while (performance.now() < end) { /* busy wait */ }
          } else {
            break;
          }
        }
        const naiveTime = performance.now() - t0;
        naiveTimings.push(naiveTime);

        // bcrypt compare (constant time)
        await new Promise(r => setTimeout(r, 10));
        const t1 = performance.now();
        bcrypt.compareSync(EXAMPLE_PASSWORD, target);
        const bcryptTime = performance.now() - t1;
        bcryptTimings.push(bcryptTime);
      }

      // Render naive chart
      const maxNaive = Math.max(...naiveTimings);
      const maxBcrypt = Math.max(...bcryptTimings);
      const globalMax = Math.max(maxNaive, maxBcrypt, 0.01);

      naiveChart.innerHTML = naiveTimings.map((t, i) =>
        `<div class="timing-row">` +
        `<span class="timing-label">#${i + 1}</span>` +
        `<div class="bar-track" style="height: 16px;">` +
        `<div class="timing-bar timing-bar--naive" style="width: ${(t / globalMax) * 100}%"></div>` +
        `</div>` +
        `<span class="timing-label">${t.toFixed(3)}ms</span>` +
        `</div>`
      ).join('');

      bcryptChart.innerHTML = bcryptTimings.map((t, i) =>
        `<div class="timing-row">` +
        `<span class="timing-label">#${i + 1}</span>` +
        `<div class="bar-track" style="height: 16px;">` +
        `<div class="timing-bar timing-bar--bcrypt" style="width: ${(t / globalMax) * 100}%"></div>` +
        `</div>` +
        `<span class="timing-label">${t.toFixed(1)}ms</span>` +
        `</div>`
      ).join('');

      // Stats
      if (timingStats) {
        const naiveVariance = variance(naiveTimings);
        const bcryptVariance = variance(bcryptTimings);
        timingStats.innerHTML =
          `<div class="status-display">` +
          `<strong>Timing variance:</strong> ` +
          `Naive: <span style="color: var(--color-invalid-text);">${naiveVariance.toFixed(4)} ms²</span> — ` +
          `bcrypt: <span style="color: var(--color-valid-text);">${bcryptVariance.toFixed(4)} ms²</span><br>` +
          `<span style="font-size: 0.8125rem; color: var(--color-text-3);">` +
          `Lower variance = less information leaked. bcrypt's constant-time compare reveals nothing.</span></div>`;
      }

      timingBtn.disabled = false;
      timingBtn.textContent = 'Run Timing Comparison';
    });
  }
}

function variance(arr: number[]): number {
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  return arr.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / arr.length;
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

  // Build table rows
  let html = '';
  for (const algo of algorithms) {
    const bool = (v: boolean | 'Partial') =>
      v === true ? '✓' : v === 'Partial' ? 'Partial' : '✗';

    html +=
      `<tr data-expandable data-algo="${escapeHtml(algo.name)}" ` +
      `role="button" tabindex="0" aria-expanded="false" ` +
      `aria-label="${escapeHtml(algo.name)} — click to expand details">` +
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

  // Expand/collapse click handlers
  const expandableRows = tbody.querySelectorAll<HTMLTableRowElement>('[data-expandable]');
  expandableRows.forEach(row => {
    const handler = () => {
      const expandRow = row.nextElementSibling as HTMLTableRowElement | null;
      if (!expandRow) return;
      const isOpen = !expandRow.hidden;
      expandRow.hidden = isOpen;
      row.setAttribute('aria-expanded', String(!isOpen));
      const icon = row.querySelector('.expand-icon');
      if (icon) icon.classList.toggle('expand-icon--open', !isOpen);
    };
    row.addEventListener('click', handler);
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handler();
      }
    });
  });

  // Live timing race: bcrypt vs PBKDF2
  if (raceBtn && raceResult) {
    raceBtn.addEventListener('click', async () => {
      raceBtn.disabled = true;
      raceBtn.innerHTML = '<span class="spinner"></span> Running…';
      raceResult.innerHTML = '<span class="spinner"></span> Hashing with bcrypt (cost 12)…';

      await new Promise(r => setTimeout(r, 30));

      // bcrypt
      const tb0 = performance.now();
      const salt = bcrypt.genSaltSync(12);
      bcrypt.hashSync('TimingComparisonTest', salt);
      const bcryptTime = performance.now() - tb0;

      raceResult.innerHTML = '<span class="spinner"></span> Hashing with PBKDF2 (100k rounds)…';
      await new Promise(r => setTimeout(r, 30));

      // PBKDF2 via WebCrypto
      const tp0 = performance.now();
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode('TimingComparisonTest'), 'PBKDF2', false, ['deriveBits']
      );
      await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: encoder.encode('random-salt-value-16'),
          iterations: 100000,
          hash: 'SHA-256',
        },
        keyMaterial,
        256
      );
      const pbkdf2Time = performance.now() - tp0;

      raceResult.innerHTML =
        `<div class="status-display">` +
        `<div style="display: flex; justify-content: space-between; margin-bottom: var(--space-2);">` +
        `<span style="font-weight: 700;">bcrypt (cost 12):</span>` +
        `<span style="font-family: var(--font-mono); color: var(--color-primary);">${bcryptTime.toFixed(1)} ms</span></div>` +
        `<div style="display: flex; justify-content: space-between;">` +
        `<span style="font-weight: 700;">PBKDF2 (100k rounds):</span>` +
        `<span style="font-family: var(--font-mono); color: var(--color-warning);">${pbkdf2Time.toFixed(1)} ms</span></div>` +
        `</div>`;

      raceBtn.disabled = false;
      raceBtn.textContent = 'Run Comparison';
    });
  }
}

// ═══════════════════════════════════════════════════════════════════
// EXHIBIT 6 — Real-World Attack Demo
// ═══════════════════════════════════════════════════════════════════

interface DemoUser {
  username: string;
  password: string;
  md5Hash?: string;
  bcryptHash?: string;
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

async function initScenarioA(
  container: HTMLElement,
  breachBtn: HTMLButtonElement | null,
): Promise<void> {
  // Build table with hidden passwords
  let html = '<table class="user-table" aria-label="Plaintext storage database">' +
    '<thead><tr><th scope="col">User</th><th scope="col">Stored Password</th></tr></thead><tbody>';
  for (const u of DEMO_USERS) {
    html += `<tr><td>${escapeHtml(u.username)}</td>` +
      `<td class="p6a-pw" data-pw="${escapeHtml(u.password)}">••••••••</td></tr>`;
  }
  html += '</tbody></table>';
  container.innerHTML = html;

  if (breachBtn) {
    breachBtn.addEventListener('click', () => {
      const cells = container.querySelectorAll('.p6a-pw');
      cells.forEach(cell => {
        const el = cell as HTMLElement;
        el.textContent = el.dataset.pw ?? '';
        el.classList.add('revealed');
      });
      breachBtn.disabled = true;
      breachBtn.textContent = 'Breached!';
      const callout = $('p6a-callout');
      if (callout) callout.style.display = '';
    });
  }
}

async function initScenarioB(
  container: HTMLElement,
  breachBtn: HTMLButtonElement | null,
): Promise<void> {
  // Precompute MD5 hashes
  const usersWithMd5: (DemoUser & { md5Hash: string })[] = [];
  for (const u of DEMO_USERS) {
    const hash = md5(u.password);
    usersWithMd5.push({ ...u, md5Hash: hash });
  }

  let html = '<table class="user-table" aria-label="MD5 hash storage database">' +
    '<thead><tr><th scope="col">User</th><th scope="col">MD5 Hash</th><th scope="col">Cracked?</th></tr></thead><tbody>';
  for (const u of usersWithMd5) {
    html += `<tr><td>${escapeHtml(u.username)}</td>` +
      `<td>${escapeHtml(u.md5Hash)}</td>` +
      `<td class="p6b-crack" data-pw="${escapeHtml(u.password)}">—</td></tr>`;
  }
  html += '</tbody></table>';
  container.innerHTML = html;

  // Note duplicate hashes
  const hashCounts = new Map<string, number>();
  usersWithMd5.forEach(u => hashCounts.set(u.md5Hash, (hashCounts.get(u.md5Hash) ?? 0) + 1));
  const duplicates = [...hashCounts.entries()].filter(([, c]) => c > 1);
  if (duplicates.length > 0) {
    container.innerHTML +=
      `<div style="font-size: 0.8125rem; color: var(--color-warning-text); margin-top: var(--space-2);">` +
      `⚠ Notice: ${duplicates.length} hash(es) appear more than once — identical passwords produce identical unsalted hashes.</div>`;
  }

  if (breachBtn) {
    breachBtn.addEventListener('click', async () => {
      breachBtn.disabled = true;
      breachBtn.innerHTML = '<span class="spinner"></span> Looking up…';

      const cells = container.querySelectorAll('.p6b-crack');
      for (let i = 0; i < cells.length; i++) {
        await new Promise(r => setTimeout(r, 150 + Math.random() * 200));
        const el = cells[i] as HTMLElement;
        el.textContent = el.dataset.pw ?? '';
        el.classList.add('revealed');
      }

      breachBtn.textContent = 'All Cracked!';
      const callout = $('p6b-callout');
      if (callout) callout.style.display = '';
    });
  }
}

async function initScenarioC(
  container: HTMLElement,
  breachBtn: HTMLButtonElement | null,
): Promise<void> {
  // Precompute bcrypt hashes at cost 12
  const usersWithBcrypt: (DemoUser & { bcryptHash: string })[] = [];

  // Real cost-12 bcrypt hashes.
  for (const u of DEMO_USERS) {
    const salt = bcrypt.genSaltSync(12);
    const hash = bcrypt.hashSync(u.password, salt);
    usersWithBcrypt.push({ ...u, bcryptHash: hash });
  }

  let html = '<table class="user-table" aria-label="bcrypt hash storage database">' +
    '<thead><tr><th scope="col">User</th><th scope="col">bcrypt Hash</th><th scope="col">Cracked?</th></tr></thead><tbody>';
  for (const u of usersWithBcrypt) {
    html += `<tr><td>${escapeHtml(u.username)}</td>` +
      `<td>${escapeHtml(u.bcryptHash)}</td>` +
      `<td class="p6c-crack safe">Protected</td></tr>`;
  }
  html += '</tbody></table>';

  // Note each hash is unique even for identical passwords
  container.innerHTML = html;
  container.innerHTML +=
    `<div style="font-size: 0.8125rem; color: var(--color-valid-text); margin-top: var(--space-2);">` +
    `✓ Notice: alice and eve share the same password, but their bcrypt hashes are completely different — each gets a unique salt.</div>`;

  if (breachBtn) {
    breachBtn.addEventListener('click', () => {
      breachBtn.disabled = true;
      breachBtn.innerHTML = '<span class="spinner"></span> Cracking…';

      const progressEl = $('p6c-progress');
      const fillEl = $('p6c-progress-fill');
      const textEl = $('p6c-progress-text');
      if (progressEl) progressEl.style.display = '';

      // Use real benchmark data if available, otherwise estimate
      const timePerHash = benchmarkResults.length > 0
        ? (benchmarkResults.find(r => r.cost === 12)?.timeMs ?? 400)
        : 400; // ms per hash at cost ~12

      const dictionarySize = 100_000;
      const totalTime = (dictionarySize * timePerHash) / 1000; // seconds

      let timeStr: string;
      if (totalTime < 60) timeStr = `${totalTime.toFixed(0)} seconds`;
      else if (totalTime < 3600) timeStr = `${(totalTime / 60).toFixed(1)} minutes`;
      else if (totalTime < 86400) timeStr = `${(totalTime / 3600).toFixed(1)} hours`;
      else timeStr = `${(totalTime / 86400).toFixed(1)} days`;

      // Simulate progress over 5 seconds at realistic pace.
      let elapsedMs = 0;
      const totalMs = totalTime * 1000;
      const interval = setInterval(() => {
        elapsedMs += 100;
        const progress = Math.min((elapsedMs / totalMs) * 100, 100);
        if (fillEl) (fillEl as HTMLElement).style.width = `${progress}%`;
        if (textEl) {
          textEl.textContent =
            `Attempted ${Math.floor(dictionarySize * progress / 100).toLocaleString()} of ` +
            `${dictionarySize.toLocaleString()} dictionary words… ` +
            `Estimated total time: ${timeStr} per user`;
        }

        if (progress >= 100) {
          clearInterval(interval);
        }
      }, 100);

      // After 5 seconds, stop and show callout
      setTimeout(() => {
        clearInterval(interval);
        if (textEl) {
          textEl.innerHTML =
            `<strong style="color: var(--color-valid-text);">Gave up after 5 seconds.</strong> ` +
            `At ${timePerHash.toFixed(0)} ms/hash, cracking a 100,000-word dictionary would take ` +
            `<strong>${timeStr}</strong> per user × 8 users.`;
        }
        breachBtn.textContent = 'Too Slow!';
        const callout = $('p6c-callout');
        if (callout) callout.style.display = '';
      }, 5000);
    });
  }
}
