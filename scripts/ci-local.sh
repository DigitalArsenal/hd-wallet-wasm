#!/usr/bin/env bash
set -euo pipefail

readonly REPOSITORY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$#" -ne 0 ]]; then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi

cd "${REPOSITORY_DIR}"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
npm ci --ignore-scripts
node scripts/acquire-better-sqlite3-prebuild.mjs
npm run test:offline-contracts
npm run build:release
npm run build:docs
npm run test:release
npm run test:native
npm run test:wasm
npm run test:wallet-ui
npm run test:relay
npm run test:browser
npm run test:packed
npm run verify:release -- --version 2.0.28 --source-ref HEAD --skip-tag
git diff --exit-code
test -z "$(git status --porcelain=v1 --untracked-files=all)"
