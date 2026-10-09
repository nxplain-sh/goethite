#!/bin/sh
# After the .deb or .rpm package is installed or upgraded.
#
# A first install leaves goethite stopped: port 53 is often taken (by
# systemd-resolved, for one), and the config should be checked first. On an
# upgrade, a running goethite hands over to the new binary in place: it
# starts it, passes it its sockets and its store, and exits once the new one
# answers, so no query is dropped. If the new one fails to start, the old one
# carries on.
#
# dpkg calls this with `configure <previously configured version>` (empty on a
# first install); rpm with the number of versions installed afterwards
# (1 on a first install).
set -e

first_install=false
case "$1" in
    configure) [ -z "${2:-}" ] && first_install=true ;;
    1) first_install=true ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    if [ "$first_install" = false ] && systemctl is-active --quiet goethite.service; then
        systemctl kill --signal=SIGUSR2 --kill-whom=main goethite.service || true
    fi
fi

if [ "$first_install" = true ]; then
    cat <<'MESSAGE'
goethite is installed but not started. Check /etc/goethite/goethite.toml, then:

    goethite check-config --config /etc/goethite/goethite.toml
    systemctl enable --now goethite

Guide: https://nxplain-sh.github.io/goethite/install/
MESSAGE
fi
