#!/usr/bin/env bash
set -Eeuo pipefail

readonly TARGET="${1:?usage: package-release.sh <rust-target> [output-directory]}"
readonly OUTPUT_DIR="${2:-dist}"
[[ "${TARGET}" == "x86_64-unknown-linux-gnu" ]] || {
  printf 'unsupported release target: %s\n' "${TARGET}" >&2
  exit 1
}
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly BINARY="${PROJECT_ROOT}/target/${TARGET}/release/vexa-vm"
readonly UPDATE_HELPER="${PROJECT_ROOT}/target/${TARGET}/release/vexa-update-helper"
readonly LINUX_GUEST_TOOLS="${PROJECT_ROOT}/guest-tools/target/x86_64-unknown-linux-gnu/release/vexa-guest-tools"
readonly WINDOWS_GUEST_TOOLS="${PROJECT_ROOT}/guest-tools/target/x86_64-pc-windows-gnu/release/vexa-guest-tools.exe"
readonly ARCHIVE="${OUTPUT_DIR}/vexa-vm-${TARGET}.tar.gz"
readonly ROOT_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${PROJECT_ROOT}/Cargo.toml" | head -n1)"
readonly GUEST_TOOLS_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${PROJECT_ROOT}/guest-tools/Cargo.toml" | head -n1)"

[[ -s "${PROJECT_ROOT}/Cargo.lock" && -s "${PROJECT_ROOT}/guest-tools/Cargo.lock" ]] || {
  printf 'committed root and Guest Tools Cargo.lock files are required for a release\n' >&2
  exit 1
}
[[ -n "${ROOT_VERSION}" && "${ROOT_VERSION}" == "${GUEST_TOOLS_VERSION}" ]] || {
  printf 'application and Guest Tools release versions must match (app=%s guest-tools=%s)\n' \
    "${ROOT_VERSION:-missing}" "${GUEST_TOOLS_VERSION:-missing}" >&2
  exit 1
}

[[ -x "${BINARY}" ]] || {
  printf 'release binary not found: %s\n' "${BINARY}" >&2
  exit 1
}
[[ -x "${UPDATE_HELPER}" ]] || {
  printf 'update helper binary not found: %s\n' "${UPDATE_HELPER}" >&2
  exit 1
}
[[ -x "${LINUX_GUEST_TOOLS}" ]] || {
  printf 'Linux Guest Tools release binary not found: %s\n' "${LINUX_GUEST_TOOLS}" >&2
  exit 1
}
[[ -f "${WINDOWS_GUEST_TOOLS}" ]] || {
  printf 'Windows Guest Tools release binary not found: %s\n' "${WINDOWS_GUEST_TOOLS}" >&2
  exit 1
}
[[ -f "${PROJECT_ROOT}/static/css/app.css" ]] || {
  printf 'compiled Tailwind asset is missing; run npm run build first\n' >&2
  exit 1
}
[[ -f "${PROJECT_ROOT}/static/vendor/novnc/core/rfb.js" ]] || {
  printf 'vendored noVNC asset is missing; run npm run build first\n' >&2
  exit 1
}

mkdir -p "${OUTPUT_DIR}"
staging="$(mktemp -d)"
cleanup() { rm -rf "${staging}"; }
trap cleanup EXIT

install -Dm0755 "${BINARY}" "${staging}/bin/vexa-vm"
install -Dm0755 "${UPDATE_HELPER}" "${staging}/bin/vexa-update-helper"
install -Dm0755 "${LINUX_GUEST_TOOLS}" "${staging}/guest-tools/vexa-guest-tools-linux-x86_64"
install -Dm0644 "${WINDOWS_GUEST_TOOLS}" "${staging}/guest-tools/vexa-guest-tools-windows-x86_64.exe"
cp -a "${PROJECT_ROOT}/templates" "${staging}/templates"
cp -a "${PROJECT_ROOT}/static" "${staging}/static"
cp -a "${PROJECT_ROOT}/migrations" "${staging}/migrations"
cp -a "${PROJECT_ROOT}/deploy" "${staging}/deploy"
cp -a "${PROJECT_ROOT}/docs" "${staging}/docs"
install -m0644 "${PROJECT_ROOT}/README.md" "${staging}/README.md"
install -m0644 "${PROJECT_ROOT}/LICENSE" "${staging}/LICENSE"
printf '%s\n' "${ROOT_VERSION}" > "${staging}/VERSION"

unsafe_link="$(find "${staging}" -type l -print -quit)"
[[ -z "${unsafe_link}" ]] || {
  printf 'release payload contains a symbolic link: %s\n' "${unsafe_link}" >&2
  exit 1
}
unsafe_special="$(find "${staging}" ! -type f ! -type d -print -quit)"
[[ -z "${unsafe_special}" ]] || {
  printf 'release payload contains a special filesystem entry: %s\n' "${unsafe_special}" >&2
  exit 1
}

tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime='UTC 2020-01-01' -czf "${ARCHIVE}" -C "${staging}" \
  bin templates static migrations deploy docs guest-tools VERSION README.md LICENSE
(cd "${OUTPUT_DIR}" && sha256sum "$(basename "${ARCHIVE}")" > "$(basename "${ARCHIVE}").sha256")
printf '%s\n' "${ARCHIVE}"
