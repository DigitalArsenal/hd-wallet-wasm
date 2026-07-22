#!/usr/bin/env bash
set -euo pipefail

# Build the frozen OpenSSL FIPS provider for WebAssembly from verified source.

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BUILD_DIR="${SCRIPT_DIR}/build"
readonly DIST_DIR="${SCRIPT_DIR}/dist"
readonly OPENSSL_VERSION='3.0.9'
readonly OPENSSL_SHA256='eb1ab04781474360f77c318ab89d8c5a03abc38e63d65a603cabbf1b00a1dc90'
readonly OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
readonly OPENSSL_INSTALL_PREFIX='/hd-wallet-build/openssl-3.0.9'
readonly OPENSSL_OPENSSLDIR="${OPENSSL_INSTALL_PREFIX}/ssl"
readonly EMSDK_DIR="${SCRIPT_DIR}/../build-wasm/_deps/emsdk-src"
readonly EMSCRIPTEN_DIR="${EMSDK_DIR}/upstream/emscripten"

TEMP_ROOT=''

log() {
  printf '[openssl-fips] %s\n' "$*"
}

die() {
  printf '[openssl-fips] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${TEMP_ROOT}" && -d "${TEMP_ROOT}" ]]; then
    rm -rf -- "${TEMP_ROOT}"
  fi
}
trap cleanup EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

compute_sha256() {
  local file="$1"
  local output
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum -- "${file}")" || die 'could not hash OpenSSL archive'
  elif command -v shasum >/dev/null 2>&1; then
    output="$(shasum -a 256 -- "${file}")" || die 'could not hash OpenSSL archive'
  else
    die 'required SHA-256 utility not found'
  fi
  digest="${output%% *}"
  case "${digest}" in
    ''|*[!0-9a-f]*) die 'SHA-256 utility returned a malformed digest' ;;
  esac
  [[ "${#digest}" -eq 64 ]] || die 'SHA-256 utility returned a malformed digest'
  printf '%s' "${digest}"
}

check_prerequisites() {
  require_command curl
  require_command make
  require_command perl
  require_command tar

  if [[ -x "${EMSCRIPTEN_DIR}/emcc" ]]; then
    export PATH="${EMSCRIPTEN_DIR}:${PATH}"
    export EMSDK="${EMSDK_DIR}"
    export EM_CONFIG="${EMSDK_DIR}/.emscripten"
  fi
  for command_name in emar emcc emmake emranlib; do
    require_command "${command_name}"
  done
  emcc --version | head -n 1 | grep -F '3.1.51' >/dev/null \
    || die 'Emscripten must be exactly 3.1.51'
}

reject_unsafe_archive() {
  local archive="$1"
  local listing="${TEMP_ROOT}/archive-paths.txt"
  tar -tzf "${archive}" > "${listing}"
  [[ -s "${listing}" ]] || die 'OpenSSL archive is empty'

  while IFS= read -r entry; do
    [[ -n "${entry}" ]] || die 'OpenSSL archive contains an empty path'
    case "${entry}" in
      /*|../*|*/../*|*/..)
        die "OpenSSL archive path escapes extraction root: ${entry}"
        ;;
    esac
    case "${entry}" in
      "openssl-${OPENSSL_VERSION}"|"openssl-${OPENSSL_VERSION}/"*) ;;
      *) die "OpenSSL archive has an unexpected top-level path: ${entry}" ;;
    esac
  done < "${listing}"

  if LC_ALL=C tar -tvzf "${archive}" | awk '
    {
      kind = substr($1, 1, 1)
      if (kind != "-" && kind != "d") unsafe = 1
    }
    END { exit unsafe ? 0 : 1 }
  '; then
    die 'OpenSSL archive contains a link or special file'
  fi
}

prepare_verified_source() {
  local archive
  local actual_sha256
  local source_parent="${TEMP_ROOT}/source"
  archive="$(mktemp "${TEMP_ROOT}/openssl-source.XXXXXX.tar.gz")"
  mkdir -p "${source_parent}"

  log "downloading OpenSSL ${OPENSSL_VERSION} to a new temporary file"
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "${archive}" "${OPENSSL_URL}"
  actual_sha256="$(compute_sha256 "${archive}")"
  [[ "${actual_sha256}" == "${OPENSSL_SHA256}" ]] \
    || die 'OpenSSL archive SHA-256 does not match the frozen digest'
  reject_unsafe_archive "${archive}"
  tar --extract --gzip --file "${archive}" \
    --directory "${source_parent}" --no-same-owner --no-same-permissions

  SOURCE_DIR="${source_parent}/openssl-${OPENSSL_VERSION}"
  [[ -d "${SOURCE_DIR}" && ! -L "${SOURCE_DIR}" ]] \
    || die 'verified OpenSSL source directory is absent or redirected'
  readonly SOURCE_DIR
}

configure_and_build() {
  local jobs
  jobs="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || printf '4')"
  export AR=emar
  export CC=emcc
  export CFLAGS='-Os -fno-exceptions -DOPENSSL_NO_SECURE_MEMORY -DOPENSSL_SMALL_FOOTPRINT -D__STDC_NO_ATOMICS__'
  export RANLIB=emranlib

  mkdir -p "${STAGED_DIST}"
  cd "${SOURCE_DIR}"
  ./Configure linux-generic32 \
    --prefix="${OPENSSL_INSTALL_PREFIX}" \
    --openssldir="${OPENSSL_OPENSSLDIR}" \
    no-asm \
    no-threads \
    no-shared \
    no-dso \
    no-engine \
    no-async \
    no-sock \
    no-dgram \
    no-tests \
    no-ui-console \
    enable-fips
  emmake make -j"${jobs}" build_libs
}

reject_ephemeral_paths() {
  local archive
  for archive in "${SOURCE_DIR}/libcrypto.a" "${SOURCE_DIR}/providers/fips.a"; do
    [[ -f "${archive}" ]] || continue
    if LC_ALL=C grep -aF -- "${TEMP_ROOT}" "${archive}" >/dev/null \
        || LC_ALL=C grep -aF -- 'hd-wallet-openssl.' "${archive}" >/dev/null; then
      die "OpenSSL output embeds an ephemeral build path: ${archive}"
    fi
  done
  LC_ALL=C grep -aF -- "${OPENSSL_INSTALL_PREFIX}" "${SOURCE_DIR}/libcrypto.a" >/dev/null \
    || die 'OpenSSL output does not contain the deterministic install prefix'
}

stage_output() {
  mkdir -p "${STAGED_DIST}/include" "${STAGED_DIST}/lib"
  cp "${SOURCE_DIR}/libcrypto.a" "${STAGED_DIST}/lib/libcrypto.a"
  if [[ -f "${SOURCE_DIR}/providers/fips.a" ]]; then
    cp "${SOURCE_DIR}/providers/fips.a" "${STAGED_DIST}/lib/fips.a"
  fi
  cp -R "${SOURCE_DIR}/include/openssl" "${STAGED_DIST}/include/openssl"
  [[ -s "${STAGED_DIST}/lib/libcrypto.a" ]] || die 'libcrypto.a is missing or empty'

  # These paths are fixed descendants of SCRIPT_DIR. Existing output is never
  # used as a build input; only a fully verified new staged result is installed.
  [[ "${BUILD_DIR}" == "${SCRIPT_DIR}/build" ]] || die 'invalid build directory'
  [[ "${DIST_DIR}" == "${SCRIPT_DIR}/dist" ]] || die 'invalid dist directory'
  rm -rf -- "${BUILD_DIR}" "${DIST_DIR}"
  mv "${STAGED_DIST}" "${DIST_DIR}"
}

main() {
  check_prerequisites
  TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/hd-wallet-openssl.XXXXXX")"
  STAGED_DIST="${TEMP_ROOT}/dist"
  readonly STAGED_DIST
  prepare_verified_source
  configure_and_build
  reject_ephemeral_paths
  stage_output
  log "verified OpenSSL ${OPENSSL_VERSION} WebAssembly output installed at ${DIST_DIR}"
}

main "$@"
