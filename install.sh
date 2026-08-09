#!/usr/bin/env bash
set -Eeuo pipefail

readonly APP_NAME="vexa-vm"
readonly INSTALL_ROOT="/opt/vexa-vm"
readonly RELEASES_ROOT="${INSTALL_ROOT}/releases"
readonly CURRENT_LINK="${INSTALL_ROOT}/current"
readonly STATE_ROOT="/var/lib/vexa-vm"
readonly CONFIG_ROOT="/etc/vexa-vm"
readonly UPDATE_TRUST_STORE="${CONFIG_ROOT}/update-trusted-keys.json"
readonly SERVICE_USER="vexa"
readonly VERSION="${VEXA_VERSION:-latest}"
readonly REPOSITORY="ItzGlace/vaxa-vm"
readonly BIND_ADDRESS="${VEXA_BIND:-127.0.0.1:8080}"

log() { printf '\033[1;36m[vexa-vm]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[vexa-vm]\033[0m %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "run this installer as root (pipe it to sudo bash)"
[[ "$(uname -s)" == "Linux" ]] || fail "Vexa-VM requires Linux"
command -v systemctl >/dev/null || fail "systemd is required"
[[ "${VEXA_REPOSITORY:-${REPOSITORY}}" == "${REPOSITORY}" ]] \
  || fail "VEXA_REPOSITORY overrides are not accepted by production installs"

case "$(uname -m)" in
  x86_64) release_arch="x86_64-unknown-linux-gnu" ;;
  *) fail "this release supports x86_64 KVM hosts; detected: $(uname -m)" ;;
esac

install_packages() {
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl openssl sqlite3 \
      qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients virtinst \
      cloud-image-utils genisoimage p7zip-full dnsmasq-base iproute2 nftables
  elif command -v dnf >/dev/null; then
    dnf install -y ca-certificates curl openssl sqlite qemu-kvm qemu-img libvirt \
      libvirt-client virt-install cloud-utils-growpart genisoimage p7zip p7zip-plugins dnsmasq iproute nftables
  else
    fail "supported package manager not found (apt-get or dnf required)"
  fi
}

log "installing KVM/libvirt runtime dependencies"
install_packages
for required_command in awk base64 curl find openssl sed sha256sum sort stat tar uniq; do
  command -v "${required_command}" >/dev/null \
    || fail "required installer command is unavailable: ${required_command}"
done
systemctl enable --now libvirtd

if ! virsh net-info default >/dev/null 2>&1 \
  && [[ -f /usr/share/libvirt/networks/default.xml ]]; then
  virsh net-define /usr/share/libvirt/networks/default.xml >/dev/null
fi
if virsh net-info default >/dev/null 2>&1; then
  virsh net-autostart default >/dev/null
  if ! LC_ALL=C virsh net-info default | grep -q '^Active:.*yes'; then
    virsh net-start default >/dev/null
  fi
fi

if [[ ! -e /dev/kvm ]]; then
  log "warning: /dev/kvm is absent; the panel will install but real VM creation will remain unavailable"
fi

if ! getent group "${SERVICE_USER}" >/dev/null; then
  groupadd --system "${SERVICE_USER}"
fi
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${SERVICE_USER}" --home-dir "${STATE_ROOT}" \
    --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
for group_name in libvirt kvm; do
  getent group "${group_name}" >/dev/null && usermod -a -G "${group_name}" "${SERVICE_USER}"
done

install -d -o root -g root -m 0755 "${INSTALL_ROOT}" "${RELEASES_ROOT}"
if [[ -e "${CURRENT_LINK}" || -L "${CURRENT_LINK}" ]]; then
  fail "a versioned Vexa-VM install already exists; use the signed panel update workflow"
fi
# QEMU runs as libvirt-qemu and must be able to traverse the state root to
# reach the group-protected ISO/cloud-init stores. It still cannot list the
# directory or read the private database/configuration files.
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0751 "${STATE_ROOT}"
install -d -o "${SERVICE_USER}" -g kvm -m 2750 \
  "${STATE_ROOT}/isos" "${STATE_ROOT}/cloud-init"
install -d -o "${SERVICE_USER}" -g kvm -m 2770 "${STATE_ROOT}/guest-tools"
install -d -o root -g root -m 0755 "${STATE_ROOT}/updates"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0700 \
  "${STATE_ROOT}/updates/staged" "${STATE_ROOT}/updates/requests"
install -d -o root -g root -m 0700 \
  "${STATE_ROOT}/updates/processing" "${STATE_ROOT}/updates/processed" \
  "${STATE_ROOT}/updates/rollback" "/var/lib/vexa-vm/update-helper" \
  "/var/lib/vexa-vm/update-helper/receipts"
install -d -o root -g root -m 0755 "${STATE_ROOT}/updates/status"
install -d -o "${SERVICE_USER}" -g kvm -m 2770 /var/lib/libvirt/images/vexa-vm
install -d -o root -g "${SERVICE_USER}" -m 0750 "${CONFIG_ROOT}"

release_base="https://github.com/${REPOSITORY}/releases"
if [[ "${VERSION}" == "latest" ]]; then
  archive_url="${release_base}/latest/download/vexa-vm-${release_arch}.tar.gz"
else
  archive_url="${release_base}/download/${VERSION}/vexa-vm-${release_arch}.tar.gz"
fi
archive="$(mktemp)"
checksum="$(mktemp)"
archive_entries="$(mktemp)"
release_partial=""
trust_decoded=""
trust_temporary=""
cleanup() {
  rm -f -- "${archive}" "${checksum}" "${archive_entries}"
  [[ -z "${trust_decoded}" ]] || rm -f -- "${trust_decoded}"
  [[ -z "${trust_temporary}" ]] || rm -f -- "${trust_temporary}"
  if [[ -n "${release_partial}" \
    && "${release_partial}" == "${RELEASES_ROOT}"/.install.* ]]; then
    rm -rf -- "${release_partial}"
  fi
}
trap cleanup EXIT

log "downloading ${archive_url}"
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 \
  --max-time 3600 --retry 3 --max-filesize 1073741824 "${archive_url}" -o "${archive}"
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 \
  --max-time 60 --retry 3 --max-filesize 65536 "${archive_url}.sha256" -o "${checksum}"
[[ "$(stat -c '%s' "${archive}")" -gt 0 \
  && "$(stat -c '%s' "${archive}")" -le 1073741824 ]] \
  || fail "release archive is outside its compressed size limit"
expected="$(awk 'NR==1 {print $1}' "${checksum}")"
actual="$(sha256sum "${archive}" | awk '{print $1}')"
[[ "${expected}" =~ ^[a-fA-F0-9]{64}$ && "${expected,,}" == "${actual,,}" ]] || fail "release checksum verification failed"

# The bootstrap checksum is not treated as release authorization. Still parse
# the archive as hostile: only the same roots accepted by the update executor
# may be materialized, and links/special files are rejected after extraction.
tar -tzf "${archive}" > "${archive_entries}"
[[ -s "${archive_entries}" ]] || fail "release archive is empty"
[[ "$(wc -l < "${archive_entries}")" -le 32768 ]] \
  || fail "release archive contains too many entries"
duplicate_entry="$(LC_ALL=C sort "${archive_entries}" | uniq -d | head -n1)"
[[ -z "${duplicate_entry}" ]] || fail "release archive contains duplicate paths"
while IFS= read -r entry; do
  normalized="${entry%/}"
  [[ -n "${normalized}" && "${normalized}" != /* && "${normalized}" != *\\* ]] \
    || fail "release archive contains an unsafe path"
  [[ "${#normalized}" -le 1024 ]] || fail "release archive path is too long"
  IFS='/' read -r -a components <<< "${normalized}"
  for component in "${components[@]}"; do
    [[ -n "${component}" && "${component}" != "." && "${component}" != ".." ]] \
      || fail "release archive contains a traversal path"
    [[ "${#component}" -le 255 ]] || fail "release archive path component is too long"
  done
  case "${components[0]}" in
    bin|templates|static|migrations|deploy|docs|guest-tools)
      ;;
    VERSION|README.md|LICENSE)
      [[ "${#components[@]}" -eq 1 ]] || fail "release archive root file is nested"
      ;;
    *) fail "release archive contains a non-allowlisted root" ;;
  esac
done < "${archive_entries}"
while IFS= read -r verbose_entry; do
  case "${verbose_entry:0:1}" in
    -|d) ;;
    *) fail "release archive contains a link or special file" ;;
  esac
done < <(tar -tvzf "${archive}")
tar --numeric-owner -tvzf "${archive}" | awk '
  substr($1, 1, 1) == "-" {
    if ($3 > 536870912) exit 1
    total += $3
    if (total > 2147483648) exit 1
  }
' || fail "release archive exceeds its unpacked size limits"

release_partial="$(mktemp -d "${RELEASES_ROOT}/.install.XXXXXX")"
tar --extract --gzip --file "${archive}" --directory "${release_partial}" \
  --no-same-owner --no-same-permissions --delay-directory-restore
[[ -f "${release_partial}/bin/vexa-vm" && ! -L "${release_partial}/bin/vexa-vm" \
  && -f "${release_partial}/bin/vexa-update-helper" && ! -L "${release_partial}/bin/vexa-update-helper" \
  && -f "${release_partial}/templates/base.html" && ! -L "${release_partial}/templates/base.html" \
  && -f "${release_partial}/static/css/app.css" && ! -L "${release_partial}/static/css/app.css" \
  && -f "${release_partial}/deploy/vexa-vm.service" && ! -L "${release_partial}/deploy/vexa-vm.service" \
  && -f "${release_partial}/deploy/vexa-update-executor-ready.service" && ! -L "${release_partial}/deploy/vexa-update-executor-ready.service" \
  && -f "${release_partial}/deploy/vexa-update-dispatch.service" && ! -L "${release_partial}/deploy/vexa-update-dispatch.service" \
  && -f "${release_partial}/deploy/vexa-update-dispatch.path" && ! -L "${release_partial}/deploy/vexa-update-dispatch.path" \
  && -f "${release_partial}/VERSION" && ! -L "${release_partial}/VERSION" ]] \
  || fail "release archive is missing a required regular file"
required_runtime_files=(
  README.md LICENSE
  templates/docs.html templates/error.html templates/isos.html templates/login.html
  templates/logs.html templates/network.html templates/overall.html templates/public_base.html
  templates/settings.html templates/status.html templates/vm_create.html
  templates/vm_detail.html templates/vms.html templates/vnc.html
  static/images/vexa-vm-emblem.png static/js/app.js
  static/vendor/novnc/LICENSE.txt static/vendor/novnc/core/rfb.js
  guest-tools/vexa-guest-tools-linux-x86_64
  guest-tools/vexa-guest-tools-windows-x86_64.exe
)
for relative in "${required_runtime_files[@]}"; do
  [[ -f "${release_partial}/${relative}" && ! -L "${release_partial}/${relative}" ]] \
    || fail "release archive is missing required runtime file: ${relative}"
done
[[ -z "$(find "${release_partial}" -type l -print -quit)" ]] \
  || fail "release archive extracted a symbolic link"
[[ -z "$(find "${release_partial}" ! -type f ! -type d -print -quit)" ]] \
  || fail "release archive extracted a special file"

[[ "$(wc -c < "${release_partial}/VERSION")" -le 128 \
  && "$(awk 'END {print NR}' "${release_partial}/VERSION")" -eq 1 ]] \
  || fail "release VERSION has an invalid length or line count"
release_version="$(awk 'NR == 1 {sub(/\r$/, ""); print}' "${release_partial}/VERSION")"
[[ "${release_version}" =~ ^((0|[1-9][0-9]*)\.){2}(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] \
  || fail "release contains an invalid semantic VERSION"
if [[ "${VERSION}" != "latest" ]]; then
  [[ "${VERSION#v}" == "${release_version}" ]] \
    || fail "downloaded release VERSION does not match VEXA_VERSION"
fi
release_destination="${RELEASES_ROOT}/${release_version}"
[[ ! -e "${release_destination}" && ! -L "${release_destination}" ]] \
  || fail "release ${release_version} is already installed; use the signed panel update workflow"

chown -R root:root "${release_partial}"
find "${release_partial}" -type d -exec chmod 0755 {} +
find "${release_partial}" -type f -exec chmod 0644 {} +
chmod 0755 "${release_partial}/bin/vexa-vm" "${release_partial}/bin/vexa-update-helper"
chmod 0755 "${release_partial}/guest-tools/vexa-guest-tools-linux-x86_64"
chmod 0644 "${release_partial}/guest-tools/vexa-guest-tools-windows-x86_64.exe"
mv "${release_partial}" "${release_destination}"
release_partial=""

temporary_current="${INSTALL_ROOT}/.current-${release_version}-$$"
[[ ! -e "${temporary_current}" && ! -L "${temporary_current}" ]] \
  || fail "temporary active-release link already exists"
ln -s "releases/${release_version}" "${temporary_current}"
mv -Tf "${temporary_current}" "${CURRENT_LINK}"

guest_tools_version="${release_version}"
[[ "${guest_tools_version}" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] \
  || fail "release contains an invalid Guest Tools version"

generated_password=""
if [[ ! -f "${CONFIG_ROOT}/vexa-vm.env" ]]; then
  master_key="$(openssl rand -base64 32 | tr -d '\n')"
  generated_password="$(openssl rand -base64 24 | tr -d '\n')"
  host_ip="$(ip -j route get 1.1.1.1 2>/dev/null | sed -n 's/.*"prefsrc":"\([^"]*\)".*/\1/p' | head -n1)"
  public_url="${VEXA_PUBLIC_URL:-http://${host_ip:-127.0.0.1}:${BIND_ADDRESS##*:}}"
  secure_cookies=false
  [[ "${public_url}" == https://* ]] && secure_cookies=true
  umask 077
  {
    printf 'VEXA_BIND=%s\n' "${BIND_ADDRESS}"
    printf 'VEXA_PUBLIC_URL=%s\n' "${public_url}"
    printf 'VEXA_DATABASE=%s/vexa.db\n' "${STATE_ROOT}"
    printf 'VEXA_TEMPLATE_DIR=%s/templates\n' "${CURRENT_LINK}"
    printf 'VEXA_STATIC_DIR=%s/static\n' "${CURRENT_LINK}"
    printf 'VEXA_SECURE_COOKIES=%s\n' "${secure_cookies}"
    printf 'VEXA_MASTER_KEY=%s\n' "${master_key}"
    printf 'VEXA_BOOTSTRAP_ADMIN=admin\n'
    printf 'VEXA_BOOTSTRAP_PASSWORD=%s\n' "${generated_password}"
    printf 'VEXA_HYPERVISOR=auto\nVEXA_LIBVIRT_URI=qemu:///system\n'
    printf 'VEXA_VM_STORAGE=/var/lib/libvirt/images/vexa-vm\n'
    printf 'VEXA_ISO_STORAGE=%s/isos\n' "${STATE_ROOT}"
    printf 'VEXA_CLOUD_INIT_STORAGE=%s/cloud-init\n' "${STATE_ROOT}"
    printf 'VEXA_GUEST_TOOLS_SOCKET_DIR=%s/guest-tools\n' "${STATE_ROOT}"
    printf 'VEXA_GUEST_TOOLS_LINUX_X86_64_ARTIFACT=%s/guest-tools/vexa-guest-tools-linux-x86_64\n' "${CURRENT_LINK}"
    printf 'VEXA_GUEST_TOOLS_WINDOWS_X86_64_ARTIFACT=%s/guest-tools/vexa-guest-tools-windows-x86_64.exe\n' "${CURRENT_LINK}"
    printf 'VEXA_NETWORK_BRIDGE=virbr0\n'
    printf 'VEXA_VNC_TTL_SECONDS=600\nVEXA_METRICS_INTERVAL_SECONDS=15\nVEXA_LOG=info\n'
  } > "${CONFIG_ROOT}/vexa-vm.env"
  chown root:"${SERVICE_USER}" "${CONFIG_ROOT}/vexa-vm.env"
  chmod 0640 "${CONFIG_ROOT}/vexa-vm.env"
fi

# Preserve explicit external administrator paths, while migrating legacy
# /opt/vexa-vm defaults to the atomic /opt/vexa-vm/current release link.
ensure_release_setting() {
  local key="$1" legacy_value="$2" release_value="$3" count current_value
  count="$(grep -c "^${key}=" "${CONFIG_ROOT}/vexa-vm.env" || true)"
  [[ "${count}" -le 1 ]] || fail "${key} is duplicated in vexa-vm.env"
  if [[ "${count}" -eq 0 ]]; then
    printf '%s=%s\n' "${key}" "${release_value}" >> "${CONFIG_ROOT}/vexa-vm.env"
    return
  fi
  current_value="$(sed -n "s|^${key}=||p" "${CONFIG_ROOT}/vexa-vm.env")"
  if [[ "${current_value}" == "${legacy_value}" || "${current_value}" == "${release_value}" ]]; then
    sed -i "s|^${key}=.*|${key}=${release_value}|" "${CONFIG_ROOT}/vexa-vm.env"
  fi
}
ensure_release_setting "VEXA_TEMPLATE_DIR" \
  "${INSTALL_ROOT}/templates" "${CURRENT_LINK}/templates"
ensure_release_setting "VEXA_STATIC_DIR" \
  "${INSTALL_ROOT}/static" "${CURRENT_LINK}/static"
ensure_release_setting "VEXA_GUEST_TOOLS_SOCKET_DIR" \
  "${STATE_ROOT}/guest-tools" "${STATE_ROOT}/guest-tools"
ensure_release_setting "VEXA_GUEST_TOOLS_LINUX_X86_64_ARTIFACT" \
  "${INSTALL_ROOT}/guest-tools/vexa-guest-tools-linux-x86_64" \
  "${CURRENT_LINK}/guest-tools/vexa-guest-tools-linux-x86_64"
ensure_release_setting "VEXA_GUEST_TOOLS_WINDOWS_X86_64_ARTIFACT" \
  "${INSTALL_ROOT}/guest-tools/vexa-guest-tools-windows-x86_64.exe" \
  "${CURRENT_LINK}/guest-tools/vexa-guest-tools-windows-x86_64.exe"
guest_tools_linux_path="$(sed -n 's|^VEXA_GUEST_TOOLS_LINUX_X86_64_ARTIFACT=||p' "${CONFIG_ROOT}/vexa-vm.env")"
guest_tools_windows_path="$(sed -n 's|^VEXA_GUEST_TOOLS_WINDOWS_X86_64_ARTIFACT=||p' "${CONFIG_ROOT}/vexa-vm.env")"
if [[ "${guest_tools_linux_path}" == "${CURRENT_LINK}/guest-tools/vexa-guest-tools-linux-x86_64" \
  && "${guest_tools_windows_path}" == "${CURRENT_LINK}/guest-tools/vexa-guest-tools-windows-x86_64.exe" ]]; then
  # Bundled Guest Tools are built at the application release version. Leaving
  # the override absent lets each signed self-update advertise its own compile
  # time version without mutating the root-owned environment file.
  sed -i '/^VEXA_GUEST_TOOLS_VERSION=/d' "${CONFIG_ROOT}/vexa-vm.env"
elif ! grep -q '^VEXA_GUEST_TOOLS_VERSION=' "${CONFIG_ROOT}/vexa-vm.env"; then
  # Preserve an explicit administrator version for external artifact paths.
  printf 'VEXA_GUEST_TOOLS_VERSION=%s\n' "${guest_tools_version}" >> "${CONFIG_ROOT}/vexa-vm.env"
fi
chown root:"${SERVICE_USER}" "${CONFIG_ROOT}/vexa-vm.env"
chmod 0640 "${CONFIG_ROOT}/vexa-vm.env"

# A release-signing public key may be pinned during bootstrap. The key is
# public, but only root may replace this trust decision. If no key is supplied,
# panel updates remain visibly disabled and no privileged watcher is started.
update_key_id="${VEXA_UPDATE_KEY_ID:-}"
update_public_key="${VEXA_UPDATE_PUBLIC_KEY_B64:-}"
if [[ -n "${update_key_id}" || -n "${update_public_key}" ]]; then
  [[ -n "${update_key_id}" && -n "${update_public_key}" ]] \
    || fail "VEXA_UPDATE_KEY_ID and VEXA_UPDATE_PUBLIC_KEY_B64 must be provided together"
  [[ "${update_key_id}" =~ ^[A-Za-z0-9._:@/-]{1,128}$ ]] \
    || fail "VEXA_UPDATE_KEY_ID is invalid"
  [[ "${update_public_key}" =~ ^[A-Za-z0-9+/]{43}=$ ]] \
    || fail "VEXA_UPDATE_PUBLIC_KEY_B64 must encode one raw 32-byte Ed25519 key"
  trust_decoded="$(mktemp)"
  printf '%s' "${update_public_key}" | base64 --decode > "${trust_decoded}" \
    || fail "VEXA_UPDATE_PUBLIC_KEY_B64 is invalid"
  [[ "$(stat -c '%s' "${trust_decoded}")" -eq 32 ]] \
    || fail "VEXA_UPDATE_PUBLIC_KEY_B64 did not decode to 32 bytes"
  trust_temporary="${CONFIG_ROOT}/.update-trusted-keys.$$"
  [[ ! -e "${trust_temporary}" && ! -L "${trust_temporary}" ]] \
    || fail "temporary update trust-store path already exists"
  umask 077
  printf '{\n  "schema_version": 1,\n  "keys": [{"key_id": "%s", "public_key_base64": "%s"}]\n}\n' \
    "${update_key_id}" "${update_public_key}" > "${trust_temporary}"
  chown root:root "${trust_temporary}"
  chmod 0644 "${trust_temporary}"
  mv -f "${trust_temporary}" "${UPDATE_TRUST_STORE}"
  trust_temporary=""
fi
if [[ -e "${UPDATE_TRUST_STORE}" || -L "${UPDATE_TRUST_STORE}" ]]; then
  [[ -f "${UPDATE_TRUST_STORE}" && ! -L "${UPDATE_TRUST_STORE}" \
    && "$(stat -c '%u' "${UPDATE_TRUST_STORE}")" -eq 0 ]] \
    || fail "the update trust store must be a root-owned regular file"
  chmod go-w "${UPDATE_TRUST_STORE}"
fi

for unit in vexa-vm.service vexa-update-executor-ready.service \
  vexa-update-dispatch.service vexa-update-dispatch.path; do
  install -o root -g root -m 0644 "${CURRENT_LINK}/deploy/${unit}" \
    "/etc/systemd/system/${unit}"
done
systemctl daemon-reload
systemctl enable vexa-vm.service
systemctl restart vexa-vm.service

service_healthy=false
for attempt in {1..20}; do
  if curl --silent --fail "http://127.0.0.1:${BIND_ADDRESS##*:}/healthz" >/dev/null; then
    service_healthy=true
    break
  fi
  sleep 1
done
if ! systemctl is-active --quiet vexa-vm.service || [[ "${service_healthy}" != true ]]; then
  journalctl -u vexa-vm.service --no-pager -n 50 >&2
  fail "service failed its startup health check"
fi

# The first successful start has persisted an Argon2id hash in SQLite. Keep the
# one-time value only in this installer's memory so it does not become a
# long-lived secret in the systemd environment file.
if [[ -n "${generated_password}" ]]; then
  sed -i '/^VEXA_BOOTSTRAP_PASSWORD=/d' "${CONFIG_ROOT}/vexa-vm.env"
  chmod 0640 "${CONFIG_ROOT}/vexa-vm.env"
fi

if [[ -f "${UPDATE_TRUST_STORE}" && -x /usr/bin/apt-get && -x /usr/bin/dpkg-query ]]; then
  if systemctl start vexa-update-executor-ready.service; then
    systemctl enable vexa-update-executor-ready.service \
      vexa-update-dispatch.service vexa-update-dispatch.path
    systemctl start vexa-update-dispatch.service
    systemctl start vexa-update-dispatch.path
    log "signed panel updates are enabled"
  else
    systemctl disable vexa-update-executor-ready.service \
      vexa-update-dispatch.service vexa-update-dispatch.path >/dev/null 2>&1 || true
    log "warning: update executor self-check failed; panel updates remain disabled"
  fi
else
  rm -f -- /run/vexa-vm/update-executor.ready
  systemctl disable vexa-update-executor-ready.service \
    vexa-update-dispatch.service vexa-update-dispatch.path >/dev/null 2>&1 || true
  log "signed panel updates remain disabled until a release public key is pinned"
fi

log "installation complete"
if [[ -n "${generated_password}" ]]; then
  printf '\nAdmin username: admin\nAdmin password: %s\n\nChange this password after first login.\n' "${generated_password}"
fi
log "configuration: ${CONFIG_ROOT}/vexa-vm.env"
log "service logs: journalctl -u vexa-vm -f"
if [[ "${BIND_ADDRESS}" == 127.0.0.1:* ]]; then
  log "the secure default listens on loopback; configure deploy/nginx.conf with TLS for remote access"
fi
