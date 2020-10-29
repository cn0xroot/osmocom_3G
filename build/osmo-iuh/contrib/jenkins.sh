#!/usr/bin/env bash

set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

mkdir "$deps" || true
rm -rf "$inst"

osmo-build-dep.sh libosmocore

"$deps"/libosmocore/contrib/verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"

osmo-build-dep.sh libosmo-abis
osmo-build-dep.sh libosmo-netif sysmocom/sctp
osmo-build-dep.sh libosmo-sccp sysmocom/iu
osmo-build-dep.sh libasn1c

# the asn1c binary is used by the 'regen' target below
osmo-build-dep.sh asn1c aper-prefix

set +x
echo
echo
echo
echo " =============================== osmo-iuh ==============================="
echo
set -x

autoreconf --install --force
./configure

# Verify that checked-in asn1 code is identical to regenerated asn1 code
PATH="$inst/bin:$PATH" $MAKE $PARALLEL_MAKE -C src regen

# attempt to settle the file system
sleep 1

git status
git diff | cat

if ! git diff-files --quiet ; then
	echo "ERROR: 'make -C src regen' does not match committed asn1 code"
	exit 1
fi

$MAKE $PARALLEL_MAKE
$MAKE check \
  || cat-testlogs.sh
$MAKE distcheck \
  || cat-testlogs.sh
