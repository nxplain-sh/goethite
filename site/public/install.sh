#!/bin/sh
# Installs goethite on this Linux machine from its GitHub release:
#
#   curl -fsSL https://nxplain-sh.github.io/goethite/install.sh | sh
#
# It picks the .deb, the .rpm or the tarball for this distribution and
# architecture, checks the download against the release's SHA256SUMS, and
# installs the binary, the systemd units and (only when there is none yet)
# /etc/goethite/goethite.toml. It does not start goethite: check the config
# first, as the message at the end says. `sh -s -- 0.5.0` installs a
# particular version instead of the latest; so does GOETHITE_VERSION=0.5.0.
#
# The script is served from the documentation site and lives in the
# repository, where it can be read before it is piped to a shell:
# https://github.com/nxplain-sh/goethite/blob/main/site/public/install.sh
#
# shortcut: the download is checked against SHA256SUMS from the same release,
# not against the build attestation. Upgrading to `gh attestation verify`
# (which needs more tools on the machine) is for when goethite leaves 0.x.
# See https://nxplain-sh.github.io/goethite/verify/.

set -eu

repo=nxplain-sh/goethite
release=https://github.com/$repo/releases/download

die() {
    printf 'goethite: %s\n' "$1" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] ||
    die "goethite runs on Linux only; macOS is for development (see https://nxplain-sh.github.io/goethite/quick-start/)"
command -v curl >/dev/null || die "curl is needed to download the release"
command -v sha256sum >/dev/null || die "sha256sum (coreutils) is needed to check the download"

if [ "$(id -u)" -eq 0 ]; then
    as_root() { "$@"; }
else
    command -v sudo >/dev/null || die "run this script as root, or install sudo"
    as_root() { sudo "$@"; }
fi

case "$(uname -m)" in
    x86_64 | amd64) deb_arch=amd64; arch=x86_64 ;;
    aarch64 | arm64) deb_arch=arm64; arch=aarch64 ;;
    *) die "no goethite release for $(uname -m); it is built for amd64 and arm64" ;;
esac

version=${1:-${GOETHITE_VERSION:-}}
if [ -z "$version" ]; then
    version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
        sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
    [ -n "$version" ] || die "could not find the latest release; pass one, as in: sh -s -- 0.5.0"
fi
version=${version#v}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# -f fails on a 404, --proto keeps redirects on https.
fetch() {
    curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" || die "could not download $1"
}

check() {
    grep "  $1\$" "$tmp/SHA256SUMS" > "$tmp/checksum" || die "SHA256SUMS has no line for $1"
    (cd "$tmp" && sha256sum -c checksum) >/dev/null || die "the download does not match SHA256SUMS"
}

fetch "$release/v$version/SHA256SUMS" "$tmp/SHA256SUMS"

if command -v apt-get >/dev/null && command -v dpkg >/dev/null; then
    file="goethite_${version}-1_${deb_arch}.deb"
    fetch "$release/v$version/$file" "$tmp/$file"
    check "$file"
    as_root apt-get install -y "$tmp/$file"
elif command -v dnf >/dev/null; then
    file="goethite-${version}-1.${arch}.rpm"
    fetch "$release/v$version/$file" "$tmp/$file"
    check "$file"
    as_root dnf install -y "$tmp/$file"
else
    file="goethite-${version}-${arch}-unknown-linux-gnu.tar.gz"
    fetch "$release/v$version/$file" "$tmp/$file"
    check "$file"
    (cd "$tmp" && tar -xzf "$file")
    dir="$tmp/goethite-${version}-${arch}-unknown-linux-gnu"
    as_root install -d -m 0755 /etc/goethite /etc/goethite/lists /etc/systemd/system
    as_root install -m 0755 "$dir/goethite" /usr/bin/goethite
    as_root install -m 0644 "$dir"/systemd/*.service /etc/systemd/system/
    [ -e /etc/goethite/goethite.toml ] ||
        as_root install -m 0644 "$dir/goethite.toml" /etc/goethite/goethite.toml
    if [ -d /run/systemd/system ]; then
        as_root systemctl daemon-reload
    fi
    # The package's postinstall says this in the two branches above.
    printf '\ngoethite %s is installed but not started. Check /etc/goethite/goethite.toml, then:\n\n' "$version"
    printf '    goethite check-config --config /etc/goethite/goethite.toml\n'
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
        printf '    systemctl enable --now goethite\n'
    fi
    printf '\nGuide: https://nxplain-sh.github.io/goethite/install/\n'
fi
