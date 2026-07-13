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
      `<span class="anatomy-legend__dot" style="background-color: var(--color-${item.cls})"></span>` +
      `<span>${item.label}</span></div>`,
    ).join('');

    arrows.innerHTML =
      '<span style="color:var(--color-version)"> ↑  </span>' +
      '<span style="color:var(--color-cost)"> ↑ </span>' +
      '<span style="color:var(--color-salt)">←———— 22 chars ————→</span>' +
      '<span style="color:var(--color-hash)">←————————— 31 chars —————————→</span>';
  });

  initEksSchedule();
  init72ByteLimit();
  wireTermTooltips();
}

/**
 * "Why bcrypt is slow" — an honest visualization of Eksblowfish's
 * `expensive_key_schedule`. This does NOT fake a hash: it mirrors the real
 * control flow of bcrypt's setup (bcrypt_setup → EksBlowfishSetup):
 *
 *   1. Blowfish is initialized (P-array + 4 S-boxes = 4 KB of state).
 *   2. The state is keyed once with the salt and once with the password.
 *   3. Then the loop runs 2^cost times, each iteration re-keying the state
 *      alternately with the salt and the password. THAT loop is "the cost".
 *
 * We animate a representative sample of the S-box words being rewritten and
 * report the true round count (2^cost). The real hashing still happens in the
 * worker via bcryptjs; this panel explains the mechanism, it does not replace it.
 */
function initEksSchedule(): void {
  const slider = $('p1-eks-cost') as HTMLInputElement | null;
  const costValue = $('p1-eks-cost-value');
  const roundsEl = $('p1-eks-rounds');
  const runBtn = $('p1-eks-run-btn') as HTMLButtonElement | null;
  const sboxesEl = $('p1-eks-sboxes');
  const progressEl = $('p1-eks-progress');
  const stageEl = $('p1-eks-stage');
  if (!slider || !runBtn || !sboxesEl || !progressEl) return;

  // 8x8 grid of cells standing in for a sample of the 1,042 32-bit state words.
  const CELLS = 64;
  sboxesEl.innerHTML = Array.from({ length: CELLS }, (_, i) =>
    `<span class="eks-cell" data-i="${i}"></span>`).join('');
  const cells = Array.from(sboxesEl.querySelectorAll<HTMLElement>('.eks-cell'));

  const renderRounds = (cost: number): void => {
    if (roundsEl) {
      roundsEl.innerHTML =
        `cost ${cost} → 2<sup>${cost}</sup> = ` +
        `<strong style="color: var(--color-warning-text);">${(2 ** cost).toLocaleString()}</strong> key-expansion rounds`;
    }
  };

  slider.addEventListener('input', () => {
    const cost = parseInt(slider.value, 10);
    if (costValue) costValue.textContent = String(cost);
    slider.setAttribute('aria-valuenow', String(cost));
    renderRounds(cost);
  });
  renderRounds(parseInt(slider.value, 10));

  let animating = false;
  runBtn.addEventListener('click', async () => {
    if (animating) return;
    animating = true;
    runBtn.disabled = true;
    if (stageEl) stageEl.classList.add('eks-stage--active');

    const cost = parseInt(slider.value, 10);
    const totalRounds = 2 ** cost;
    // Show a fixed number of visual frames regardless of cost, but always report
    // the TRUE round count so the number — not the animation length — carries the
    // lesson (cost 14 would be 16,384 real rounds; we don't wait for all of them).
    const FRAMES = Math.min(totalRounds, 40);
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const frameMs = reduced ? 0 : 45;

    for (let f = 0; f < FRAMES; f++) {
      const usingSalt = f % 2 === 0; // real Eksblowfish alternates salt / key
      // Rewrite a scatter of state cells this round.
      for (let k = 0; k < 10; k++) {
        const cell = cells[Math.floor(Math.random() * cells.length)];
        cell.className = `eks-cell eks-cell--hot ${usingSalt ? 'eks-cell--salt' : 'eks-cell--pw'}`;
      }
      const shownRound = Math.round(((f + 1) / FRAMES) * totalRounds);
      progressEl.innerHTML =
        `Round <strong>${shownRound.toLocaleString()}</strong> of <strong>${totalRounds.toLocaleString()}</strong> — ` +
        `re-mixing the <span style="color: ${usingSalt ? 'var(--color-salt)' : 'var(--color-version)'};">` +
        `${usingSalt ? 'salt' : 'password'}</span> into the 4&nbsp;KB Blowfish state.`;
      if (frameMs) await new Promise(r => setTimeout(r, frameMs));
    }

    cells.forEach(c => { c.className = 'eks-cell eks-cell--done'; });
    progressEl.innerHTML =
      `Done: the key schedule ran <strong>2<sup>${cost}</sup> = ${totalRounds.toLocaleString()}</strong> rounds. ` +
      `Each +1 to cost <strong>doubles</strong> that count — this is the “work” that “cost doubles.” ` +
      `The finished 4&nbsp;KB state becomes the Blowfish key that encrypts bcrypt's magic string into the hash.`;

    runBtn.disabled = false;
    animating = false;
  });
}

/**
 * The 72-byte limit made visceral. We hash password A in the worker (a real
 * bcrypt hash), then verify password B against it. When A and B share a 72-byte
 * prefix, bcryptjs itself reports a match — no faking: bcrypt truly ignores
 * bytes past 72, so the real primitive returns true.
 */
function init72ByteLimit(): void {
  const aInput = $('p1-72-a') as HTMLInputElement | null;
  const bInput = $('p1-72-b') as HTMLInputElement | null;
  const prefixEl = $('p1-72-prefix');
  const runBtn = $('p1-72-run-btn') as HTMLButtonElement | null;
  const resultEl = $('p1-72-result');
  if (!aInput || !bInput || !runBtn || !resultEl) return;

  const byteLen = (s: string): number => new TextEncoder().encode(s).length;

  const sharedPrefixBytes = (a: string, b: string): number => {
    const ea = new TextEncoder().encode(a);
    const eb = new TextEncoder().encode(b);
    let i = 0;
    while (i < ea.length && i < eb.length && ea[i] === eb[i]) i++;
    return i;
  };

  const updatePrefix = (): void => {
    if (!prefixEl) return;
    const shared = sharedPrefixBytes(aInput.value, bInput.value);
    const aLen = byteLen(aInput.value);
    const bLen = byteLen(bInput.value);
    const collide = shared >= 72 && aLen > 72 && bLen > 72;
    prefixEl.innerHTML =
      `A is ${aLen} bytes, B is ${bLen} bytes; they share the first ` +
      `<strong style="color: var(--color-text);">${shared}</strong> bytes. ` +
      (collide
        ? `<span style="color: var(--color-warning-text);">Both exceed 72 bytes and agree through byte 72 — bcrypt will treat them as identical.</span>`
        : `<span style="color: var(--color-text-3);">Make both longer than 72 bytes while keeping the first 72 identical to force a collision.</span>`);
  };

  aInput.addEventListener('input', updatePrefix);
  bInput.addEventListener('input', updatePrefix);
  updatePrefix();

  runBtn.addEventListener('click', async () => {
    const a = aInput.value;
    const b = bInput.value;
    if (!a || !b) {
      resultEl.innerHTML = '<div class="status-display">Enter both passwords.</div>';
      return;
    }
    runBtn.disabled = true;
    runBtn.innerHTML = '<span class="spinner"></span> Hashing A &amp; verifying B…';
    resultEl.innerHTML = '';

    try {
      const { hash } = await cryptoClient.hash(a, 10);
      const { match } = await cryptoClient.compare(b, hash);
      const identical = a === b;
      const cls = match ? 'verify-result--no-match' : 'verify-result--match';
      // Note: here a MATCH is the *alarming* outcome (B ≠ A yet verifies), so we
      // paint a positive verify with the danger style and say so in words + icon.
      const icon = match ? '⚠' : '✓';
      const headline = match
        ? (identical
            ? 'Match — the two passwords are identical, so of course B verifies.'
            : 'Match — B is a DIFFERENT password, yet it verifies against A’s hash!')
        : 'No match — these differ within the first 72 bytes, so bcrypt tells them apart.';
      resultEl.innerHTML =
        `<div class="verify-result ${cls}">${icon} ${escapeHtml(headline)}</div>` +
        `<div class="status-display" style="font-family: var(--font-mono); font-size: 0.75rem; word-break: break-all;">` +
        `bcrypt.compare(B, hash(A)) → <strong>${match ? 'true' : 'false'}</strong><br>hash(A) = ${escapeHtml(hash)}</div>` +
        (match && !identical
          ? `<div class="status-display" style="font-size: 0.8125rem;">Everything after byte 72 was discarded before hashing. In production, truncate-and-warn or pre-hash long inputs (e.g. SHA-256 → base64) before bcrypt.</div>`
          : '');
    } catch (err) {
      resultEl.innerHTML = `<div class="verify-result verify-result--no-match">Failed: ${escapeHtml(String(err))}</div>`;
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = 'Hash A, then verify B against it';
    }
  });
}

/**
 * First-use inline definitions. A `.term` span carries its own `.term__tip`
 * child (a tooltip). We make it keyboard-operable: focus or click toggles
 * aria-expanded and a visible class; Escape closes it.
 */
function wireTermTooltips(): void {
  document.querySelectorAll<HTMLElement>('.term').forEach(term => {
    const open = (state: boolean): void => {
      term.setAttribute('aria-expanded', String(state));
      term.classList.toggle('term--open', state);
    };
    term.addEventListener('click', () => open(term.getAttribute('aria-expanded') !== 'true'));
    term.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(term.getAttribute('aria-expanded') !== 'true'); }
      else if (e.key === 'Escape') open(false);
    });
    term.addEventListener('focus', () => open(true));
    term.addEventListener('blur', () => open(false));
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

    // The login "sweet spot": ~250 ms is the classic threshold below which a
    // hash feels instant to a human logging in. It's a target, not a hard wall,
    // so we draw it as a marker line the bars cross rather than a hard zone.
    const LOGIN_MS = 250;
    const loginPct = Math.min(100, (LOGIN_MS / maxTime) * 100);

    let chartHtml = '<div class="zone-label zone-label--danger">⚠ Danger zone (cost &lt; 10)</div>';
    for (const r of results) {
      const pct = (r.timeMs / maxTime) * 100;
      const multiplier = (r.timeMs / baseTime).toFixed(1);
      const isSafe = r.cost >= 10;
      const instant = r.timeMs <= LOGIN_MS;
      if (r.cost === 10) {
        chartHtml += '<div class="zone-label zone-label--safe">✓ Safe zone (cost ≥ 10)</div>';
      }
      chartHtml +=
        `<div class="bar-row">` +
        `<span class="bar-label">${r.cost}</span>` +
        `<div class="bar-track">` +
        // Marker line at the ~250 ms human-perception threshold.
        `<span class="bar-threshold" style="left: ${loginPct}%" aria-hidden="true"></span>` +
        `<div class="bar-fill ${isSafe ? 'bar-fill--safe' : 'bar-fill--danger'}" ` +
        `style="width: ${pct}%"></div></div>` +
        `<span class="bar-time">${r.timeMs.toFixed(0)} ms</span>` +
        `<span class="bar-multiplier">${multiplier}×</span>` +
        `<span class="bar-verdict ${instant ? 'bar-verdict--login' : 'bar-verdict--attack'}">` +
        `${instant ? 'feels instant' : 'attacker-costly'}</span>` +
        `</div>`;
    }
    chartEl.innerHTML = chartHtml;

    const thresholdsEl = $('p3-thresholds');
    if (thresholdsEl) thresholdsEl.hidden = false;

    if (crackingEl) {
      let crackHtml =
        '<div style="margin-top: var(--space-4); padding: var(--space-4); background-color: var(--color-surface); ' +
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
      timingBtn.disabled = true;
      timingBtn.innerHTML = '<span class="spinner"></span> Running…';
      const mode =
        (document.querySelector('input[name="p4-timing-mode"]:checked') as HTMLInputElement | null)?.value ?? 'histogram';

      // Allow the spinner to paint before we hog the thread with tight loops.
      await new Promise(r => setTimeout(r, 0));

      if (mode === 'histogram') runHistogram(naiveChart, bcryptChart, timingStats);
      else runSimulated(naiveChart, bcryptChart, timingStats);

      timingBtn.disabled = false;
      timingBtn.textContent = 'Run Timing Comparison';
    });
  }
}

/** Two byte strings of equal length. `matchLen` leading bytes are identical. */
function makeProbe(matchLen: number, total: number): [string, string] {
  const shared = 'a'.repeat(matchLen);
  const target = shared + 'b'.repeat(total - matchLen);
  const guess = shared + 'c'.repeat(total - matchLen);
  return [target, guess];
}

/** Early-exit byte compare — the leaky one. */
function naiveEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Compare every byte regardless of mismatch — the constant-time one. */
function constantTimeEquals(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i % a.length) ^ b.charCodeAt(i % b.length));
  return diff === 0;
}

/**
 * REAL measurement, no busy-wait, no fabrication. We time thousands of naive vs
 * constant-time compares for a 0-byte-match probe and a near-full-match probe.
 * The mean of the near-match naive case is measurably higher because the loop
 * runs further before returning — the leak emerges from data, not a fudge factor.
 */
function runHistogram(naiveChart: HTMLElement, bcryptChart: HTMLElement, statsEl: HTMLElement | null): void {
  const TOTAL = 60;
  const TRIALS = 4000;
  const [target, mismatchGuess] = makeProbe(0, TOTAL);   // mismatch at byte 0
  const [, nearGuess] = makeProbe(TOTAL - 1, TOTAL);      // mismatch at last byte

  const timeMany = (fn: (a: string, b: string) => boolean, guess: string): number => {
    // warm up
    for (let i = 0; i < 500; i++) fn(target, guess);
    const t0 = performance.now();
    for (let i = 0; i < TRIALS; i++) fn(target, guess);
    return (performance.now() - t0) / TRIALS * 1000; // µs per compare
  };

  const naiveEarly = timeMany(naiveEquals, mismatchGuess);
  const naiveLate = timeMany(naiveEquals, nearGuess);
  const ctEarly = timeMany(constantTimeEquals, mismatchGuess);
  const ctLate = timeMany(constantTimeEquals, nearGuess);

  const row = (label: string, val: number, max: number, cls: string): string =>
    `<div class="timing-row">` +
    `<span class="timing-label">${label}</span>` +
    `<div class="bar-track" style="height: 16px;">` +
    `<div class="timing-bar ${cls}" style="width: ${Math.max(2, (val / max) * 100)}%"></div></div>` +
    `<span class="timing-label">${val.toFixed(3)}µs</span></div>`;

  const naiveMax = Math.max(naiveEarly, naiveLate, 0.001);
  const ctMax = Math.max(ctEarly, ctLate, 0.001);

  naiveChart.innerHTML =
    row('mismatch @0', naiveEarly, naiveMax, 'timing-bar--naive') +
    row('mismatch @59', naiveLate, naiveMax, 'timing-bar--naive');
  bcryptChart.innerHTML =
    row('mismatch @0', ctEarly, ctMax, 'timing-bar--bcrypt') +
    row('mismatch @59', ctLate, ctMax, 'timing-bar--bcrypt');

  const leak = naiveLate - naiveEarly;
  const ctGap = Math.abs(ctLate - ctEarly);
  if (statsEl) {
    statsEl.innerHTML =
      `<div class="status-display">` +
      `<strong>Real measurement (${TRIALS.toLocaleString()} trials each, mean µs/compare):</strong><br>` +
      `Naive === leaks <span style="color: var(--color-invalid-text);">${leak >= 0 ? '+' : ''}${leak.toFixed(3)} µs</span> ` +
      `between a byte-0 mismatch and a byte-59 mismatch — a small but real signal an attacker can average out over many requests.<br>` +
      `Constant-time gap: <span style="color: var(--color-valid-text);">${ctGap.toFixed(3)} µs</span> (noise; no dependence on match length).<br>` +
      `<span style="font-size: 0.8125rem; color: var(--color-text-3);">` +
      `These are genuine timings from your CPU, in microseconds. On a loopback network the signal is buried in noise — ` +
      `which is exactly why real attacks average thousands of samples, and why you still must use constant-time compare.</span></div>`;
  }
}

/**
 * SIMULATED mode — clearly labeled as illustrative, not measured. We amplify the
 * per-byte cost so the leak's SHAPE is obvious on screen. The numbers shown are
 * marked "simulated" so no learner mistakes them for real timings.
 */
function runSimulated(naiveChart: HTMLElement, bcryptChart: HTMLElement, statsEl: HTMLElement | null): void {
  const naiveTimings: number[] = [];
  const bcryptTimings: number[] = [];
  const TOTAL = 60;
  for (let i = 0; i < 10; i++) {
    const matchLen = Math.round((i / 9) * TOTAL);
    // Simulated: cost is proportional to how far the naive loop runs (matchLen),
    // scaled by an obvious amplification so it's visible. Constant-time is flat.
    naiveTimings.push(matchLen * 0.05 + Math.random() * 0.02);
    bcryptTimings.push(TOTAL * 0.05 + Math.random() * 0.02);
  }
  const nMax = Math.max(...naiveTimings, 0.01);
  const bMax = Math.max(...bcryptTimings, 0.01);

  naiveChart.innerHTML = naiveTimings.map((t, i) =>
    `<div class="timing-row">` +
    `<span class="timing-label">${i}/9 match</span>` +
    `<div class="bar-track" style="height: 16px;">` +
    `<div class="timing-bar timing-bar--naive" style="width: ${(t / nMax) * 100}%"></div></div>` +
    `<span class="timing-label">sim</span></div>`,
  ).join('');
  bcryptChart.innerHTML = bcryptTimings.map((t, i) =>
    `<div class="timing-row">` +
    `<span class="timing-label">${i}/9 match</span>` +
    `<div class="bar-track" style="height: 16px;">` +
    `<div class="timing-bar timing-bar--bcrypt" style="width: ${(t / bMax) * 100}%"></div></div>` +
    `<span class="timing-label">sim</span></div>`,
  ).join('');

  if (statsEl) {
    statsEl.innerHTML =
      `<div class="status-display">` +
      `<strong>⚠ Simulated / exaggerated — these bars are illustrative, not measured.</strong><br>` +
      `The naive === staircase shows the <em>shape</em> of the leak: the more leading bytes match, the longer it runs. ` +
      `A real leak is a few nanoseconds. Switch to “Measure real timings” to see the genuine (tiny) signal.<br>` +
      `<span style="font-size: 0.8125rem; color: var(--color-text-3);">` +
      `Variance — naive: <span style="color: var(--color-invalid-text);">${variance(naiveTimings).toFixed(4)}</span>, ` +
      `constant-time: <span style="color: var(--color-valid-text);">${variance(bcryptTimings).toFixed(4)}</span> (simulated units).</span></div>`;
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
    description: 'PBKDF2 applies a PRF — a pseudorandom function, a keyed primitive whose output is indistinguishable from random, here typically HMAC-SHA256 — iteratively, thousands of times. It is NIST-approved and required in FIPS environments. However, it is not memory-hard (it needs almost no RAM), making it cheap to parallelize on GPUs and ASICs.',
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
