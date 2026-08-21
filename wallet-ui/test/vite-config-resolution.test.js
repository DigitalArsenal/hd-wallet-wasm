import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import viteConfig from '../vite.config.js';

describe('Vite dependency resolution', () => {
  it('resolves Space Data Standards from the installed package root', () => {
    const sdsPackageRoot = viteConfig.resolve?.alias?.['@sds'];

    expect(sdsPackageRoot).toBeTypeOf('string');
    expect(existsSync(join(sdsPackageRoot, 'lib/js/EME/EME.js'))).toBe(true);
    expect(viteConfig.server?.fs?.allow).toContain(sdsPackageRoot);
  });
});
