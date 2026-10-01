#!/bin/sh
# Installs a prebuilt aegis binary from the GitHub releases.
#
#   curl -fsSL https://raw.githubusercontent.com/rasmsnall/aegis/main/install.sh | sh
#
# Environment:
#   AEGIS_VERSION      release to install, like v0.4.0 (default: the latest)
#   AEGIS_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
#   AEGIS_DOWNLOAD_URL where the release files are (default: GitHub; for mirrors)
set -eu

repo="rasmsnall/aegis"
version="${AEGIS_VERSION:-latest}"
dir="${AEGIS_INSTALL_DIR:-$HOME/.local/bin}"

fail() {
    echo "aegis install: $*" >&2
    exit 1
}

case "$(uname -s)" in
    Linux) os="unknown-linux-musl" ;;
    Darwin) os="apple-darwin" ;;
    *) fail "no prebuilt binary for $(uname -s); use 'cargo install mcp-aegis' (or the .zip on the releases page for Windows)" ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *) fail "no prebuilt binary for $(uname -m); use 'cargo install mcp-aegis'" ;;
esac
target="$arch-$os"
archive="aegis-$target.tar.gz"

if [ -n "${AEGIS_DOWNLOAD_URL:-}" ]; then
    base="$AEGIS_DOWNLOAD_URL"
elif [ "$version" = "latest" ]; then
    base="https://github.com/$repo/releases/latest/download"
else
    base="https://github.com/$repo/releases/download/$version"
fi

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO "$2" "$1"; }
else
    fail "needs curl or wget"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading $archive ($version)"
fetch "$base/$archive" "$tmp/$archive" || fail "could not download $base/$archive"
fetch "$base/$archive.sha256" "$tmp/$archive.sha256" || fail "could not download the checksum"

expected="$(cut -d ' ' -f 1 "$tmp/$archive.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$archive" | cut -d ' ' -f 1)"
else
    actual="$(shasum -a 256 "$tmp/$archive" | cut -d ' ' -f 1)"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for $archive"

tar xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$dir"
install -m 755 "$tmp/aegis-$target/aegis" "$dir/aegis" 2>/dev/null ||
    { cp "$tmp/aegis-$target/aegis" "$dir/aegis" && chmod 755 "$dir/aegis"; }

echo "installed $dir/aegis ($("$dir/aegis" --version))"
case ":$PATH:" in
    *":$dir:"*) ;;
    *) echo "note: $dir is not on your PATH; add it, or run $dir/aegis" ;;
esac
