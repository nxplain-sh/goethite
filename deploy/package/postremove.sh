#!/bin/sh
# After the .deb or .rpm package is removed or upgraded: systemd forgets the
# units that went away. goethite's data in /var/lib/goethite stays; delete it
# by hand if you no longer need it.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
