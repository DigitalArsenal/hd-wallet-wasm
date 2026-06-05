import { afterEach, describe, expect, it, vi } from 'vitest';
import { safeCopyText } from '../src/clipboard.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('safeCopyText', () => {
  it('uses the Clipboard API when available', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });

    await expect(safeCopyText('xpub-test')).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith('xpub-test');
  });

  it('does not throw when navigator.clipboard is unavailable', async () => {
    vi.stubGlobal('navigator', {});
    vi.stubGlobal('document', undefined);

    await expect(safeCopyText('peer-id-test')).resolves.toBe(false);
  });

  it('falls back to a transient textarea copy when direct clipboard write fails', async () => {
    const textarea = {
      value: '',
      readOnly: false,
      style: {},
      setAttribute: vi.fn(),
      focus: vi.fn(),
      select: vi.fn(),
      setSelectionRange: vi.fn(),
      remove: vi.fn(),
    };
    const document = {
      body: { appendChild: vi.fn() },
      createElement: vi.fn(() => textarea),
      execCommand: vi.fn(() => true),
    };

    vi.stubGlobal('navigator', {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) },
    });
    vi.stubGlobal('document', document);

    await expect(safeCopyText('fallback-copy')).resolves.toBe(true);
    expect(document.createElement).toHaveBeenCalledWith('textarea');
    expect(textarea.value).toBe('fallback-copy');
    expect(textarea.setAttribute).toHaveBeenCalledWith('aria-hidden', 'true');
    expect(document.body.appendChild).toHaveBeenCalledWith(textarea);
    expect(document.execCommand).toHaveBeenCalledWith('copy');
    expect(textarea.remove).toHaveBeenCalled();
  });
});
