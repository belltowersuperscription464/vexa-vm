#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  mapfile -t files < <(git ls-files)
else
  mapfile -t files < <(find . -type f \
    ! -path './node_modules/*' ! -path './target/*' ! -path './guest-tools/target/*' \
    ! -path './.git/*' ! -path './dist/*' ! -path './tmp/*' \
    ! -path '*/__pycache__/*' ! -name 'kvm.zip' -print)
fi
[[ "${#files[@]}" -gt 0 ]] || { printf 'no public files found\n' >&2; exit 1; }

customer_marker="$(printf '%s%s' 'iran' 'monitor')"
production_prefix="$(printf '%s%s' '94.' '182.')"
legacy_prefix="$(printf '%s%s' '185.' '239.')"
for pattern in "${customer_marker}" "${production_prefix}" "${legacy_prefix}"; do
  if printf '%s\0' "${files[@]}" | xargs -0 rg -n -i --fixed-strings -- "${pattern}"; then
    printf 'public source contains a forbidden customer or production marker\n' >&2
    exit 1
  fi
done

if printf '%s\0' "${files[@]}" | xargs -0 rg -n \
  -- '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{30,}'; then
  printf 'public source contains material resembling a private key or access token\n' >&2
  exit 1
fi

for file in "${files[@]}"; do
  case "${file}" in
    *.db|*.db-shm|*.db-wal|*.pem|*.p12|*.pfx|*.key|.env)
      printf 'forbidden generated or secret-bearing file: %s\n' "${file}" >&2
      exit 1
      ;;
  esac
done

printf 'public release scan passed for %s files\n' "${#files[@]}"
