#!/bin/sh

set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

mkdir "$deps" || true
rm -rf "$inst"

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"

osmo-build-dep.sh libosmocore "" ac_cv_path_DOXYGEN=false

"$deps"/libosmocore/contrib/verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

osmo-build-dep.sh libosmo-abis

set +x
echo
echo
echo
echo " =============================== osmo-hlr ==============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure
$MAKE $PARALLEL_MAKE
$MAKE check || cat-testlogs.sh
$MAKE distcheck || cat-testlogs.sh
