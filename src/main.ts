/**
 * main.ts — Entry point for crypto-lab-bcrypt-forge.
 * Initializes theme toggle, panel navigation, and all six exhibits.
 */

import {
  initExhibit1,
  initExhibit2,
  initExhibit3,
  initExhibit4,
  initExhibit5,
  initExhibit6,
} from './exhibits.ts';

// ─── Announcement helper ──────────────────────────────────────────

function announce(message: string): void {
  const el = document.getElementById('aria-announcer');
  if (el) {
    el.textContent = '';
    requestAnimationFrame(() => { el.textContent = message; });
  }
}

// ─── Theme toggle ─────────────────────────────────────────────────

function initThemeToggle(): void {
  const btn = document.getElementById('theme-toggle') as HTMLButtonElement | null;
  if (!btn) return;

  const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
  syncToggleButton(btn, current === 'dark');

  btn.addEventListener('click', () => {
    const nowDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const next = nowDark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    syncToggleButton(btn, !nowDark);
  });
}

function syncToggleButton(btn: HTMLButtonElement, dark: boolean): void {
  btn.textContent = dark ? '\u{1F319}' : '\u{2600}\u{FE0F}';
  btn.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
}

// ─── Panel navigation ─────────────────────────────────────────────

function initPanelNav(): void {
  const tabs = document.querySelectorAll<HTMLButtonElement>('.panel-tab');
  const panels = document.querySelectorAll<HTMLElement>('.panel');

  function activateTab(index: number): void {
    tabs.forEach((tab, i) => {
      const active = i === index;
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.setAttribute('tabindex', active ? '0' : '-1');
    });
    panels.forEach((panel, i) => {
      panel.hidden = i !== index;
      if (i === index) panel.setAttribute('tabindex', '-1');
    });
    announce(`Panel ${index + 1}: ${tabs[index]?.textContent?.trim() ?? ''}`);
  }

  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => activateTab(i));
    tab.addEventListener('keydown', (e) => {
      let next = i;
      if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      else return;
      e.preventDefault();
      activateTab(next);
      tabs[next]?.focus();
    });
  });
}

// ─── Init ─────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initPanelNav();
  initExhibit1();
  initExhibit2();
  initExhibit3();
  initExhibit4();
  initExhibit5();
  initExhibit6();
});
