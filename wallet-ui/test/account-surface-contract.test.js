import fs from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const repoRoot = path.resolve(import.meta.dirname, '..');

describe('account surface contract', () => {
  it('keeps logout inside the account modal and not only in outer navigation', async () => {
    const template = await fs.readFile(path.join(repoRoot, 'src/template.js'), 'utf8');

    expect(template).toContain('wallet-account-logout');
    expect(template).toContain('modal-header-actions');
  });

  it('supports host logout callbacks and opens login when account is requested while locked', async () => {
    const source = await fs.readFile(path.join(repoRoot, 'src/app.js'), 'utf8');

    expect(source).toContain('let _onLogoutCallback = null;');
    expect(source).toContain('onLogout = null');
    expect(source).toContain("document.getElementById(state.loggedIn ? 'keys-modal' : 'login-modal')");
    expect(source).toContain('handleLogoutRequest()');
  });

  it('uses svg close icons so modal close controls stay visually centered', async () => {
    const template = await fs.readFile(path.join(repoRoot, 'src/template.js'), 'utf8');
    const trustUI = await fs.readFile(path.join(repoRoot, 'src/trust-ui.js'), 'utf8');
    const styles = await fs.readFile(path.join(repoRoot, 'styles/widget.css'), 'utf8');

    expect(template).not.toContain('class="modal-close">&times;');
    expect(template).not.toContain('class="wallet-info-close" id="wallet-info-dismiss" title="Dismiss">&times;');
    expect(trustUI).not.toContain('class="modal-close">&times;');
    expect(template).toContain('modal-close-icon');
    expect(trustUI).toContain('modal-close-icon');
    expect(styles).toContain('.modal-close-icon');
    expect(styles).toContain('.wallet-info-close-icon');
  });
});
