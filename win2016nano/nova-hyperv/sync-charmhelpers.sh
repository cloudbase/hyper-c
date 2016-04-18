#!/usr/bin/env bash
set -e

sudo apt-get install git -y
TMP_DIR="/tmp/juju-powershell-modules-$(date | md5sum | awk '{print $1}')"
git clone https://github.com/cloudbase/juju-powershell-modules.git $TMP_DIR --recursive

CHARM_DIR=$(dirname $0)
for MODULE in JujuHelper JujuHooks JujuLogging JujuUtils JujuWindowsUtils Networking powershell-yaml; do
    if [[ -e "$CHARM_DIR/lib/Modules/$MODULE" ]]; then
        rm -rf "$CHARM_DIR/lib/Modules/$MODULE"
    fi
    cp -rf $TMP_DIR/$MODULE "$CHARM_DIR/lib/Modules/$MODULE"
done

rm -rf $TMP_DIR
