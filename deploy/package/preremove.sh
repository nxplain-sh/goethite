#!/bin/sh
# Before the .deb or .rpm package is removed: stop goethite and its
# floating-IP helper, unless this is the old version going away during an
# upgrade (dpkg: `upgrade`; rpm: 1 version left afterwards), when the new
# version's postinstall has already handed over.
set -e

case "$1" in
    remove | 0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now goethite-vrrp.service goethite.service >/dev/null 2>&1 || true
        fi
        ;;
esac
