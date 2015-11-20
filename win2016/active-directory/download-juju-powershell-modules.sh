#!/bin/bash

#
# Copyright 2014-2015 Cloudbase Solutions Srl
#

set -e

# Get the following CharmHelpers version:
#CHARM_HELPERS_REQUIRED_VERSION="0.33"
CHARM_HELPERS_GIT_COMMIT="92005a527acc16a55f728e3acca7ff55db576575"

REPO_NAME="juju-charm-helpers-private"
REPO_PATH=" git@bitbucket.org:cloudbase/${REPO_NAME}.git"
REPO_BRANCH="devel"
CHARM_HELPERS_PATH_FOR_JUJU_VERSION_121="hooks/Modules/"
CHARM_HELPERS_FOLDER_NAME="CharmHelpers"

if [ -d "$REPO_NAME" ]; then
    rm -rf $REPO_NAME
fi
git clone $REPO_PATH

pushd $REPO_NAME
git checkout $REPO_BRANCH
git reset --hard $CHARM_HELPERS_GIT_COMMIT
popd

if [ -d "$CHARM_HELPERS_PATH_FOR_JUJU_VERSION_121/$CHARM_HELPERS_FOLDER_NAME" ]; then
    rm -rf "$CHARM_HELPERS_PATH_FOR_JUJU_VERSION_121/$CHARM_HELPERS_FOLDER_NAME"
else
    mkdir -p $CHARM_HELPERS_PATH_FOR_JUJU_VERSION_121
fi

cp -r "$REPO_NAME/$CHARM_HELPERS_FOLDER_NAME" $CHARM_HELPERS_PATH_FOR_JUJU_VERSION_121

rm -rf $REPO_NAME
