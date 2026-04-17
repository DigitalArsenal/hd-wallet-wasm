import { spawnSync } from 'node:child_process';

const REQUIRED_PACKAGE_FILES = [
  'src/sdn-plugin.mjs',
  'src/sdn-plugin-manifest-source.mjs',
];

const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
  cwd: new URL('..', import.meta.url),
  encoding: 'utf8',
});

if (result.status !== 0) {
  throw new Error(
    `npm pack --dry-run failed with exit code ${result.status}:\n${result.stderr || result.stdout}`,
  );
}

let packSummary;
try {
  packSummary = JSON.parse(result.stdout);
} catch (error) {
  throw new Error(`Failed to parse npm pack --json output: ${error.message}`);
}

const files = new Set((packSummary?.[0]?.files ?? []).map((entry) => entry.path));
const missing = REQUIRED_PACKAGE_FILES.filter((file) => !files.has(file));

if (missing.length > 0) {
  throw new Error(
    `npm package is missing required SDN plugin files: ${missing.join(', ')}`,
  );
}
