#!/usr/bin/env bash
# Local CI for hd-wallet-wasm — replaces .github/workflows/build.yml
#
# Usage:
#   ./scripts/ci-local.sh          # run all checks
#   ./scripts/ci-local.sh quick    # native build + test only
#   ./scripts/ci-local.sh native   # native build + test
#   ./scripts/ci-local.sh wasm     # emscripten WASM build
#   ./scripts/ci-local.sh npm      # NPM package test

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-all}"
FAILED=0
PASSED=0
SKIPPED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== $1 ===${NC}"; }
pass() { echo -e "${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); }
skip() { echo -e "${YELLOW}SKIP${NC}: $1"; SKIPPED=$((SKIPPED + 1)); }

# ─── Native Build & Test ────────────────────────────────────────────────────
run_native() {
  step "Native CMake Configure"
  if cmake -B "$ROOT/build" -S "$ROOT" -DCMAKE_BUILD_TYPE=Release 2>&1; then
    pass "cmake configure"
  else
    fail "cmake configure"
    return
  fi

  step "Native Build"
  if cmake --build "$ROOT/build" --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" 2>&1; then
    pass "native build"
  else
    fail "native build"
    return
  fi

  step "Native Tests (ctest)"
  if (cd "$ROOT/build" && ctest --output-on-failure 2>&1); then
    pass "native tests"
  else
    fail "native tests"
  fi
}

# ─── WASM Build (Emscripten) ────────────────────────────────────────────────
run_wasm() {
  if ! command -v emcmake &>/dev/null; then
    skip "WASM build (emcmake not found — source emsdk_env.sh first)"
    return
  fi

  step "WASM CMake Configure"
  if emcmake cmake -B "$ROOT/build-wasi" -S "$ROOT" \
    -DCMAKE_BUILD_TYPE=Release -DHD_WALLET_BUILD_WASM=ON 2>&1; then
    pass "wasm cmake configure"
  else
    fail "wasm cmake configure"
    return
  fi

  step "WASM Build (all targets)"
  if cmake --build "$ROOT/build-wasi" --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" 2>&1; then
    pass "wasm build"
  else
    fail "wasm build"
    return
  fi

  step "Verify WASM Output"
  local ok=true
  for f in hd-wallet.wasm hd-wallet-wasi.wasm hd-wallet.js hd-wallet-inline.js; do
    if [ -f "$ROOT/build-wasi/wasm/$f" ]; then
      echo "  $f ($(wc -c < "$ROOT/build-wasi/wasm/$f") bytes)"
    else
      echo "  MISSING: $f"
      ok=false
    fi
  done

  if $ok; then
    pass "wasm output verification"
  else
    fail "wasm output verification"
  fi
}

# ─── NPM Package Test ───────────────────────────────────────────────────────
run_npm() {
  if [ ! -d "$ROOT/wasm" ]; then
    skip "npm test (no wasm/ directory)"
    return
  fi

  # Need WASM artifacts
  if [ ! -f "$ROOT/build-wasi/wasm/hd-wallet.wasm" ]; then
    skip "npm test (build WASM first: ./scripts/ci-local.sh wasm)"
    return
  fi

  step "NPM: Copy WASM artifacts"
  mkdir -p "$ROOT/wasm/dist"
  cp "$ROOT/build-wasi/wasm/hd-wallet.wasm" "$ROOT/wasm/dist/" 2>/dev/null || true
  cp "$ROOT/build-wasi/wasm/hd-wallet-wasi.wasm" "$ROOT/wasm/dist/" 2>/dev/null || true
  cp "$ROOT/build-wasi/wasm/hd-wallet.js" "$ROOT/wasm/dist/" 2>/dev/null || true
  cp "$ROOT/build-wasi/wasm/hd-wallet-inline.js" "$ROOT/wasm/dist/" 2>/dev/null || true
  cp "$ROOT/wasm/src/index.d.ts" "$ROOT/wasm/dist/" 2>/dev/null || true

  step "NPM: Install dependencies"
  (cd "$ROOT/wasm" && npm install --ignore-scripts 2>&1) || true

  step "NPM: Run tests"
  if (cd "$ROOT/wasm" && npm test 2>&1); then
    pass "npm test"
  else
    fail "npm test"
  fi

  step "NPM: Verify package"
  if (cd "$ROOT/wasm" && npm pack --dry-run 2>&1); then
    pass "npm pack"
  else
    fail "npm pack"
  fi
}

# ─── Dispatch ────────────────────────────────────────────────────────────────
case "$MODE" in
  all)
    run_native
    run_wasm
    run_npm
    ;;
  quick|native)
    run_native
    ;;
  wasm)
    run_wasm
    ;;
  npm)
    run_npm
    ;;
  *)
    echo "Usage: $0 [all|quick|native|wasm|npm]"
    exit 1
    ;;
esac

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed${NC}:  $PASSED"
echo -e "  ${RED}Failed${NC}:  $FAILED"
echo -e "  ${YELLOW}Skipped${NC}: $SKIPPED"
echo -e "${CYAN}═══════════════════════════════════════${NC}"

if [ "$FAILED" -gt 0 ]; then
  echo -e "\n${RED}CI FAILED${NC}"
  exit 1
else
  echo -e "\n${GREEN}CI PASSED${NC}"
fi
