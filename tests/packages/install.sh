#!/usr/bin/env bash
# Package tests: install the release's .deb and .rpm on the distributions
# goethite supports, check the binary and the shipped config, and remove the
# package again. On Debian 12 the .deb also runs under systemd: goethite
# starts from its unit and answers, hands over to the new binary when the
# package is upgraded (reinstalled), and stops when it is removed.
#
#   tests/packages/install.sh path/to/dist
#
# The directory holds one architecture's .deb and .rpm, as `cargo xtask dist`
# writes them to target/dist. Needs docker or podman (set ENGINE=podman),
# privileged containers for the systemd test, and network access for the
# distributions' packages.

# Commands for a container are single-quoted on purpose: they expand there.
# shellcheck disable=SC2016

set -euo pipefail

DIST=$(realpath "${1:?usage: install.sh path/to/dist}")
ENGINE=${ENGINE:-docker}
SYSTEMD=goethite-package-test

# Every container runs on the packages' architecture, whatever a cached image
# was pulled for.
DEB=$(find "$DIST" -maxdepth 1 -name 'goethite_*.deb' | head -n 1)
ARCH=${DEB##*_}
ARCH=${ARCH%.deb}
case "$ARCH" in
    amd64 | arm64) PLATFORM=linux/$ARCH ;;
    *) echo "no goethite_*_amd64.deb or goethite_*_arm64.deb in $DIST" >&2; exit 1 ;;
esac

DEB_IMAGES=(docker.io/library/debian:12 docker.io/library/ubuntu:22.04 docker.io/library/ubuntu:24.04)
RPM_IMAGES=(docker.io/rockylinux/rockylinux:9 registry.fedoraproject.org/fedora:latest)

# What every installation must pass, then the removal.
CHECK='goethite --version
goethite check-config --config /etc/goethite/goethite.toml >/dev/null 2>&1
test -f /usr/lib/systemd/system/goethite.service
test -f /usr/lib/systemd/system/goethite-vrrp.service'

for image in "${DEB_IMAGES[@]}"; do
    echo "== $image"
    "$ENGINE" run --rm --platform "$PLATFORM" -v "$DIST:/dist:ro" "$image" sh -euc "
        apt-get update -qq
        apt-get install -y -qq /dist/goethite_*.deb >/dev/null
        $CHECK
        apt-get remove -y -qq goethite >/dev/null
        test ! -e /usr/bin/goethite"
done

for image in "${RPM_IMAGES[@]}"; do
    echo "== $image"
    "$ENGINE" run --rm --platform "$PLATFORM" -v "$DIST:/dist:ro" "$image" sh -euc "
        dnf install -y -q /dist/goethite-*.rpm >/dev/null
        $CHECK
        dnf remove -y -q goethite >/dev/null
        test ! -e /usr/bin/goethite"
done

echo "== debian:12 with systemd"
cleanup() { "$ENGINE" rm -f "$SYSTEMD" >/dev/null 2>&1 || true; }
cleanup
trap cleanup EXIT
"$ENGINE" run -d --name "$SYSTEMD" --platform "$PLATFORM" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
    -v "$DIST:/dist:ro" docker.io/library/debian:12 sh -c '
        apt-get update -qq &&
        apt-get install -y -qq systemd systemd-sysv bind9-dnsutils >/dev/null &&
        exec /sbin/init' >/dev/null
inside() { "$ENGINE" exec "$SYSTEMD" "$@"; }

# Waits up to 120 s for a command in the container to succeed.
wait_for() {
    local tries=0
    until inside sh -c "$1" >/dev/null 2>&1; do
        if [ $((tries += 1)) -gt 120 ]; then
            echo "gave up waiting for: $1" >&2
            inside journalctl -u goethite --no-pager -n 50 >&2 || true
            return 1
        fi
        sleep 1
    done
}

wait_for 'systemctl list-units --no-pager'
inside sh -c 'apt-get install -y -qq /dist/goethite_*.deb >/dev/null'
# The container has no IPv6, which the shipped config also listens on.
inside sed -i 's|^listen = .*|listen = "127.0.0.1:53"|' /etc/goethite/goethite.toml
inside systemctl enable --now goethite
wait_for 'test "$(dig +short @127.0.0.1 goethite.test)" = 127.0.0.53'
echo "answers under systemd"
inside systemd-analyze security goethite --no-pager | tail -n 1

old=$(inside systemctl show -P MainPID goethite)
inside sh -c 'apt-get install -y -qq --reinstall /dist/goethite_*.deb >/dev/null'
wait_for "test \"\$(systemctl show -P MainPID goethite)\" != $old"
wait_for 'journalctl -u goethite --no-pager | grep -q "answering in place of the previous goethite"'
wait_for 'test "$(dig +short @127.0.0.1 goethite.test)" = 127.0.0.53'
echo "an upgrade hands over in place (main PID $old -> $(inside systemctl show -P MainPID goethite))"

inside sh -c 'apt-get remove -y -qq goethite >/dev/null'
if inside systemctl is-active --quiet goethite; then
    echo "goethite still runs after the package was removed" >&2
    exit 1
fi
echo "stops when removed"
