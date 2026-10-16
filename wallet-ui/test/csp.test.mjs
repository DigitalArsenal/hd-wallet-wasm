// SEC-053: the published wallet page carries a strict Content-Security-Policy
// (a <meta> tag: GitHub Pages cannot send headers), runs no inline script or
// inline style, requests only the chain and price APIs it uses, loads no
// third-party images, and refuses to run inside a frame (src/landing.js,
// tested in landing-bootstrap.test.mjs). Also pins the section-title focus
// rule of the account view.

import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { getModalHTML } from '../src/template.js';
import { devStylePolicy } from '../vite.config.js';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path) => readFileSync(resolve(ROOT, path), 'utf8');
const html = read('index.html');

function policy() {
  const tags = [...html.matchAll(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)">/gu)];
  expect(tags).toHaveLength(1);
  const directives = new Map();
  for (const part of tags[0][1].split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/u);
    if (name) directives.set(name, sources);
  }
  return { directives, index: tags[0].index };
}

describe('Content-Security-Policy meta', () => {
  it('comes first in <head>, before any script or stylesheet', () => {
    const { index } = policy();
    const head = html.slice(0, html.indexOf('</head>'));
    expect(index).toBeLessThan(head.indexOf('<script'));
    expect(index).toBeLessThan(head.indexOf('<link rel="stylesheet"'));
    expect(index).toBeGreaterThan(head.indexOf('<meta charset="UTF-8">'));
  });

  it('is strict: same-origin scripts and styles, no inline, no eval, nothing by default', () => {
    const { directives } = policy();
    expect(directives.get('default-src')).toEqual(["'none'"]);
    expect(directives.get('script-src')).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(directives.get('style-src')).toEqual(["'self'"]);
    expect(directives.get('img-src')).toEqual(["'self'", 'data:', 'blob:']);
    expect(directives.get('object-src')).toEqual(["'none'"]);
    expect(directives.get('base-uri')).toEqual(["'none'"]);
    expect(directives.get('form-action')).toEqual(["'none'"]);
    expect(directives.has('upgrade-insecure-requests')).toBe(true);
    for (const sources of directives.values()) {
      expect(sources).not.toContain("'unsafe-inline'");
      expect(sources).not.toContain("'unsafe-eval'");
      expect(sources).not.toContain('*');
      expect(sources).not.toContain('https:');
    }
    // A <meta> policy cannot carry frame-ancestors; the page refuses frames itself.
    expect(directives.has('frame-ancestors')).toBe(false);
    expect(read('src/landing.js')).toContain('window.top !== window.self');
  });

  it('connect-src lists exactly the APIs the page code calls', () => {
    const { directives } = policy();
    const allowed = new Set(directives.get('connect-src'));
    expect(allowed.has("'self'")).toBe(true);
    // Every https origin passed to fetch()/apiUrl() or listed as an RPC
    // endpoint in the page's modules.
    const sources = ['src/app.js', 'src/address-derivation.js', 'src/blockchain-trust.js', 'src/balances.js']
      .map(read)
      .join('\n')
      .replace(/\/\*[\s\S]*?\*\//gu, '')
      .replace(/^\s*\/\/.*$/gmu, '');
    const used = new Set();
    for (const match of sources.matchAll(/(?:fetch|apiUrl)\(\s*[`'"](https:\/\/[^/`'"$]+)/gu)) used.add(match[1]);
    for (const match of sources.matchAll(/^\s*'(https:\/\/[^/']+)',?\s*$/gmu)) used.add(match[1]);
    for (const match of sources.matchAll(/const ETH_RPC = '(https:\/\/[^/']+)'/gu)) used.add(match[1]);
    expect(used.size).toBeGreaterThan(5);
    for (const origin of used) expect([origin, allowed.has(origin)]).toEqual([origin, true]);
    for (const origin of allowed) {
      if (origin !== "'self'") expect([origin, used.has(origin)]).toEqual([origin, true]);
    }
  });

  it('the dev server relaxes style-src for its injected <style> tags, and only there', () => {
    const plugin = devStylePolicy();
    expect(plugin.apply).toBe('serve');
    expect(plugin.transformIndexHtml(html)).toContain("style-src 'self' 'unsafe-inline';");
    expect(html).not.toContain("'unsafe-inline'");
  });
});

describe('no inline script or style anywhere the policy applies', () => {
  const template = getModalHTML();

  it('index.html: scripts are external files; no inline handlers or style attributes', () => {
    for (const tag of html.matchAll(/<script\b[^>]*>/gu)) expect(tag[0]).toMatch(/\ssrc="[^"]+"/u);
    expect(html).not.toMatch(/<script\b[^>]*>[^<\s]/u);
    expect(html).not.toMatch(/\son[a-z]+\s*=/u);
    expect(html).not.toMatch(/\sstyle\s*=/u);
    expect(html).not.toMatch(/<style\b/u);
    expect(html).not.toMatch(/javascript:/u);
  });

  it('the injected login/account template has no inline handlers or style attributes', () => {
    expect(template).not.toMatch(/\son[a-z]+\s*=/u);
    expect(template).not.toMatch(/\sstyle\s*=/u);
    expect(template).not.toMatch(/<script\b|<style\b/u);
  });

  it('page modules never write inline style attributes or <style> elements', () => {
    for (const file of readdirSync(resolve(ROOT, 'src')).filter((name) => name.endsWith('.js'))) {
      const source = read(`src/${file}`);
      expect([file, /setAttribute\(\s*['"]style['"]/u.test(source)]).toEqual([file, false]);
      expect([file, /createElement\(\s*['"]style['"]/u.test(source)]).toEqual([file, false]);
      expect([file, /\.cssText\s*=/u.test(source)]).toEqual([file, false]);
    }
  });

  it('third-party images are self-hosted (pinned copies), not loaded from a CDN', () => {
    expect(html).not.toContain('cdn.jsdelivr.net');
    for (const icon of ['btc', 'eth', 'sol', 'atom', 'dot', 'ltc', 'doge']) {
      expect(html).toContain(`src="assets/chain-icons/${icon}.svg"`);
      expect(read(`public/assets/chain-icons/${icon}.svg`)).toMatch(/^<svg [^>]*xmlns="http:\/\/www\.w3\.org\/2000\/svg"/u);
      expect(read(`public/assets/chain-icons/${icon}.svg`)).not.toMatch(/<script|on[a-z]+=|href="http/iu);
    }
  });

  it('the AI-credits panel is styled from a stylesheet identical to the CSS its script would inject', () => {
    const script = read('public/assets/ai-credits/ai-credits.js');
    const match = script.match(/var CSS =([\s\S]*?);\n\n/u);
    expect(match).not.toBeNull();
    // eslint-disable-next-line no-new-func
    const css = Function(`return (${match[1]});`)();
    const sheet = read('public/assets/ai-credits/ai-credits.css');
    expect(sheet.slice(sheet.indexOf('*/') + 3).trim()).toBe(css.trim());
    expect(html).toContain('<link rel="stylesheet" href="assets/ai-credits/ai-credits.css">');
  });
});

describe('section titles: no focus box for programmatic focus', () => {
  it('tabindex=-1 headings drop the outline only for :focus:not(:focus-visible); keyboard focus keeps it', () => {
    for (const path of ['styles/account.css', 'styles/widget.css']) {
      const css = read(path);
      expect(css).toMatch(/\[tabindex="-1"\]:focus:not\(:focus-visible\)\s*\{\s*outline:\s*none;\s*\}/u);
      // Nothing removes the outline from a keyboard-focused (:focus-visible)
      // title, or from every focused title.
      for (const rule of css.matchAll(/([^{}]*)\{([^}]*)\}/gu)) {
        if (!/outline:\s*(?:none|0)\b/u.test(rule[2])) continue;
        for (const selector of rule[1].split(',').map((part) => part.trim())) {
          if (!/tabindex="-1"|pane-title/u.test(selector)) continue;
          expect(selector).toMatch(/:focus:not\(:focus-visible\)$/u);
        }
      }
    }
    expect(read('src/ui-dom.js')).toContain('titleEl.tabIndex = -1;');
  });
});
