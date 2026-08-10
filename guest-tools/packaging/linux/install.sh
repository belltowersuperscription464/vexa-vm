#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --binary PATH --secret-file PATH [--channel PATH]" >&2
  exit 2
}

binary_source=""
secret_source=""
channel_path="/dev/virtio-ports/com.vexa.guest_tools.0"
installed_binary="/usr/local/sbin/vexa-guest-tools"
installed_secret="/etc/vexa-guest-tools/secret"
installed_config="/etc/vexa-guest-tools/config.json"
installed_unit="/etc/systemd/system/vexa-guest-tools.service"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      [[ $# -ge 2 ]] || usage
      binary_source="$2"
      shift 2
      ;;
    --secret-file)
      [[ $# -ge 2 ]] || usage
      secret_source="$2"
      shift 2
      ;;
    --channel)
      [[ $# -ge 2 ]] || usage
      channel_path="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || { echo "installer must run as root" >&2; exit 1; }
[[ -f "${binary_source}" ]] || { echo "guest-tools binary was not found" >&2; exit 1; }
[[ -f "${secret_source}" ]] || { echo "per-VM secret file was not found" >&2; exit 1; }
[[ "${channel_path}" == /dev/virtio-ports/* ]] || { echo "channel must be a virtio-ports device" >&2; exit 1; }
for destination in "${installed_binary}" "${installed_secret}" "${installed_config}" "${installed_unit}"; do
  [[ ! -L "${destination}" ]] || { echo "refusing symbolic-link install target: ${destination}" >&2; exit 1; }
done
[[ ! -L /etc/vexa-guest-tools ]] || { echo "refusing symbolic-link configuration directory" >&2; exit 1; }

install -d -m 0700 /etc/vexa-guest-tools
backup_directory="$(mktemp -d /var/tmp/vexa-guest-tools-install.XXXXXX)"
config_temp="${backup_directory}/config.json.new"
published=false
installation_succeeded=false
service_was_enabled=false
service_was_active=false
binary_existed=false
secret_existed=false
config_existed=false
unit_existed=false

[[ -e "${installed_binary}" ]] && binary_existed=true
[[ -e "${installed_secret}" ]] && secret_existed=true
[[ -e "${installed_config}" ]] && config_existed=true
[[ -e "${installed_unit}" ]] && unit_existed=true
if systemctl cat vexa-guest-tools.service >/dev/null 2>&1; then
  systemctl is-enabled --quiet vexa-guest-tools.service && service_was_enabled=true
  systemctl is-active --quiet vexa-guest-tools.service && service_was_active=true
fi

[[ "${binary_existed}" == true ]] && cp -a -- "${installed_binary}" "${backup_directory}/binary"
[[ "${secret_existed}" == true ]] && cp -a -- "${installed_secret}" "${backup_directory}/secret"
[[ "${config_existed}" == true ]] && cp -a -- "${installed_config}" "${backup_directory}/config"
[[ "${unit_existed}" == true ]] && cp -a -- "${installed_unit}" "${backup_directory}/unit"

finish_installation() {
  exit_status=$?
  trap - EXIT
  set +e
  if [[ "${installation_succeeded}" != true && "${published}" == true ]]; then
    systemctl stop vexa-guest-tools.service >/dev/null 2>&1
    if [[ "${binary_existed}" == true ]]; then cp -a -- "${backup_directory}/binary" "${installed_binary}"; else rm -f -- "${installed_binary}"; fi
    if [[ "${secret_existed}" == true ]]; then cp -a -- "${backup_directory}/secret" "${installed_secret}"; else rm -f -- "${installed_secret}"; fi
    if [[ "${config_existed}" == true ]]; then cp -a -- "${backup_directory}/config" "${installed_config}"; else rm -f -- "${installed_config}"; fi
    if [[ "${unit_existed}" == true ]]; then cp -a -- "${backup_directory}/unit" "${installed_unit}"; else rm -f -- "${installed_unit}"; fi
    systemctl daemon-reload >/dev/null 2>&1
    if [[ "${service_was_enabled}" == true ]]; then
      systemctl enable vexa-guest-tools.service >/dev/null 2>&1
    else
      systemctl disable vexa-guest-tools.service >/dev/null 2>&1
    fi
    if [[ "${service_was_active}" == true ]]; then
      systemctl start vexa-guest-tools.service >/dev/null 2>&1
    fi
    echo "Vexa Guest Tools installation failed; the previous installation was restored" >&2
  fi
  rm -f -- "${config_temp}" "${backup_directory}/binary" "${backup_directory}/secret" \
    "${backup_directory}/config" "${backup_directory}/unit"
  rmdir -- "${backup_directory}" >/dev/null 2>&1
  exit "${exit_status}"
}
trap finish_installation EXIT

CHANNEL_PATH="${channel_path}" python3 -c 'import json,os,sys; json.dump({"channel_path":os.environ["CHANNEL_PATH"],"secret_file":"/etc/vexa-guest-tools/secret","max_clock_skew_seconds":120,"replay_cache_capacity":4096,"reconnect_delay_seconds":2,"policy":{"password":True,"hostname":True,"dns":True,"network":True,"ssh_keys":True,"power":True,"allowed_users":[]}},sys.stdout,separators=(",",":"))' > "${config_temp}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
published=true
install -m 0755 "${binary_source}" "${installed_binary}"
install -m 0600 "${secret_source}" "${installed_secret}"
install -m 0600 "${config_temp}" "${installed_config}"
install -m 0644 "${script_directory}/vexa-guest-tools.service" "${installed_unit}"
systemctl daemon-reload
systemctl enable vexa-guest-tools.service
systemctl reset-failed vexa-guest-tools.service 2>/dev/null || true
systemctl restart vexa-guest-tools.service

service_ready=false
main_pid=""
restart_count=""
for _ in {1..30}; do
  if systemctl is-active --quiet vexa-guest-tools.service; then
    main_pid="$(systemctl show vexa-guest-tools.service --property=MainPID --value)"
    restart_count="$(systemctl show vexa-guest-tools.service --property=NRestarts --value)"
    if [[ "${main_pid}" =~ ^[1-9][0-9]*$ ]]; then
      service_ready=true
      break
    fi
  fi
  sleep 0.5
done

if [[ "${service_ready}" != true ]]; then
  systemctl --no-pager --full status vexa-guest-tools.service >&2 || true
  journalctl --no-pager -u vexa-guest-tools.service -n 50 >&2 || true
  echo "Vexa Guest Tools did not become active after installation" >&2
  exit 1
fi

# Catch fast startup failures (invalid configuration, secret or executable) before reporting a
# successful install. Channel absence is expected and is retried by the active service.
sleep 2
current_pid="$(systemctl show vexa-guest-tools.service --property=MainPID --value)"
current_restart_count="$(systemctl show vexa-guest-tools.service --property=NRestarts --value)"
if ! systemctl is-active --quiet vexa-guest-tools.service \
  || [[ "${current_pid}" != "${main_pid}" ]] \
  || [[ "${current_restart_count}" != "${restart_count}" ]]; then
  systemctl --no-pager --full status vexa-guest-tools.service >&2 || true
  journalctl --no-pager -u vexa-guest-tools.service -n 50 >&2 || true
  echo "Vexa Guest Tools failed its post-start health window" >&2
  exit 1
fi

installation_succeeded=true
echo "Vexa Guest Tools is installed, enabled, and active"
