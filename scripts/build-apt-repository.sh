#!/usr/bin/env bash
set -Eeuo pipefail

readonly PACKAGE="${1:?usage: build-apt-repository.sh <package.deb> <output-directory>}"
readonly OUTPUT="${2:?usage: build-apt-repository.sh <package.deb> <output-directory>}"
readonly DISTRIBUTION="stable"
readonly COMPONENT="main"
readonly ARCHITECTURE="amd64"

[[ -f "${PACKAGE}" ]] || { printf 'package not found: %s\n' "${PACKAGE}" >&2; exit 1; }
for command in apt-ftparchive dpkg-scanpackages gpg gzip; do
  command -v "${command}" >/dev/null || { printf 'missing command: %s\n' "${command}" >&2; exit 1; }
done
[[ -n "${APT_GPG_KEY_ID:-}" ]] || { printf 'APT_GPG_KEY_ID is required\n' >&2; exit 1; }

pool="${OUTPUT}/pool/${COMPONENT}/v/vexa-vm"
binary="${OUTPUT}/dists/${DISTRIBUTION}/${COMPONENT}/binary-${ARCHITECTURE}"
mkdir -p "${pool}" "${binary}"
install -m0644 "${PACKAGE}" "${pool}/$(basename "${PACKAGE}")"

(
  cd "${OUTPUT}"
  dpkg-scanpackages --arch "${ARCHITECTURE}" pool /dev/null > \
    "dists/${DISTRIBUTION}/${COMPONENT}/binary-${ARCHITECTURE}/Packages"
)
gzip -n -9 -c "${binary}/Packages" > "${binary}/Packages.gz"

cat > "${OUTPUT}/apt-release.conf" <<EOF
APT::FTPArchive::Release::Origin "Vexa-VM";
APT::FTPArchive::Release::Label "Vexa-VM";
APT::FTPArchive::Release::Suite "${DISTRIBUTION}";
APT::FTPArchive::Release::Codename "${DISTRIBUTION}";
APT::FTPArchive::Release::Architectures "${ARCHITECTURE}";
APT::FTPArchive::Release::Components "${COMPONENT}";
APT::FTPArchive::Release::Description "Vexa-VM signed Debian repository";
EOF
(
  cd "${OUTPUT}"
  apt-ftparchive -c apt-release.conf release "dists/${DISTRIBUTION}" > \
    "dists/${DISTRIBUTION}/Release"
)
rm "${OUTPUT}/apt-release.conf"

gpg --batch --yes --local-user "${APT_GPG_KEY_ID}" --armor --detach-sign \
  --output "${OUTPUT}/dists/${DISTRIBUTION}/Release.gpg" \
  "${OUTPUT}/dists/${DISTRIBUTION}/Release"
gpg --batch --yes --local-user "${APT_GPG_KEY_ID}" --clearsign \
  --output "${OUTPUT}/dists/${DISTRIBUTION}/InRelease" \
  "${OUTPUT}/dists/${DISTRIBUTION}/Release"
gpg --batch --yes --local-user "${APT_GPG_KEY_ID}" --export \
  > "${OUTPUT}/vexa-vm-archive-keyring.gpg"

cat > "${OUTPUT}/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>Vexa-VM APT repository</title>
<h1>Vexa-VM signed APT repository</h1>
<p>Installation instructions are available in the
<a href="https://github.com/ItzGlace/vexa-vm#apt-repository">Vexa-VM README</a>.</p>
HTML
