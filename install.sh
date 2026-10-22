#!/usr/bin/env bash
# Install the ipcx binary from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/lavr/ip-connection-explorer/main/install.sh | bash
#
# Environment:
#   IPCX_VERSION      release to install, e.g. 0.3.0 (default: latest)
#   IPCX_INSTALL_DIR  target directory (default: /usr/local/bin)
set -euo pipefail

REPO="lavr/ip-connection-explorer"
VERSION="${IPCX_VERSION:-}"
INSTALL_DIR="${IPCX_INSTALL_DIR:-/usr/local/bin}"

die() {
	echo "ipcx install: $*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

[ "$(uname -s)" = "Linux" ] || die "ipcx collect runs on Linux only; on other systems build from source"

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac

need curl
need tar
need sha256sum

if [ -z "$VERSION" ]; then
	latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
	VERSION="${latest##*/tag/}"
	[ -n "$VERSION" ] && [ "$VERSION" != "$latest" ] || die "cannot determine the latest release"
fi

ARCHIVE="ipcx_${VERSION}_linux_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ipcx $VERSION for linux/$ARCH"
curl -fsSL -o "$tmp/$ARCHIVE" "$BASE/$ARCHIVE" || die "cannot download $BASE/$ARCHIVE"
curl -fsSL -o "$tmp/checksums.txt" "$BASE/checksums.txt" || die "cannot download $BASE/checksums.txt"

# --ignore-missing would pass if the archive were not listed at all, so check the line explicitly.
grep -q " $ARCHIVE\$" "$tmp/checksums.txt" || die "$ARCHIVE is not listed in checksums.txt"
(cd "$tmp" && grep " $ARCHIVE\$" checksums.txt | sha256sum --check --quiet) || die "checksum mismatch for $ARCHIVE"

tar -xzf "$tmp/$ARCHIVE" -C "$tmp" ipcx

SUDO=""
if [ ! -w "$INSTALL_DIR" ] && [ "$(id -u)" -ne 0 ]; then
	need sudo
	SUDO="sudo"
fi
$SUDO install -d "$INSTALL_DIR"
$SUDO install -m 0755 "$tmp/ipcx" "$INSTALL_DIR/ipcx"

echo "Installed $("$INSTALL_DIR/ipcx" --version) to $INSTALL_DIR/ipcx"
