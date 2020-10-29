#!/usr/bin/env bash

set -ex

autoreconf --install --force
./configure
$MAKE
# currently broken $MAKE $PARALLEL_MAKE
# currently broken $MAKE distcheck
