#!/bin/sh
set -e

# Set an installation prefix, if you like.
# To run from that prefix, it must be in the LD_LIBRARY_PATH:
#   export LD_LIBRARY_PATH="$HOME/prefix_3g/lib"
# Otherwise leave emtpy to install in /usr/local:
#prefix="$HOME/prefix_3g"

if [ -z "$prefix" ]; then
  check_prefix="/usr/local"
else
  check_prefix="$prefix"
fi

echo "Please make sure all dependencies are installed. On a debian:"
echo "sudo apt-get install build-essential gcc g++ make automake autoconf libtool pkg-config libtalloc-dev libpcsclite-dev libortp-dev libsctp-dev libssl-dev libdbi-dev libdbd-sqlite3 libsqlite3-dev libpcap-dev libc-ares-dev sqlite3"
echo "(hit enter to continue)"
read acknowledge
echo

echo "checking if $check_prefix is writable..."
echo "If this fails, try"
echo "  sudo mkdir -p $check_prefix"
echo "  sudo chown -R \$USER: $check_prefix"
echo "to make $check_prefix be owned by your user."
set -x
touch "$check_prefix/check_writable"
rm "$check_prefix/check_writable"


opt_prefix=""
if [ -n "$prefix" ]; then
  export LD_LIBRARY_PATH="$prefix"/lib
  export PKG_CONFIG_PATH="$prefix"/lib/pkgconfig
  opt_prefix="--prefix=$prefix"
fi

base="$PWD"

clone_and_build() {
  name="$1"
  branch="$2"

  cd "$base"

  echo "======================= $name ======================"
  if [ ! -d "$name" ]; then
    git clone "git://git.osmocom.org/$name"
    if [ -n "$branch" ]; then
      cd "$name"
      git checkout "$branch"
      cd ..
    fi
  fi

  if [ "$name" = openbsc ]; then
    cd "openbsc/openbsc"
  else
    cd "$name"
  fi

  if [ ! -f "configure" ]; then
    autoreconf -fi
  fi

  if [ ! -f "Makefile" ]; then
    opt_enable=""
    if [ "$name" = 'openbsc' ]; then
      opt_enable="--enable-smpp --enable-osmo-bsc --enable-nat --enable-iu"
    fi

    ./configure $opt_prefix $opt_enable
  fi

  make -j || make || make
  #if [ "$name" != asn1c ]; then
  #  make check
  #fi
  make install
}

clone_and_build libosmocore
clone_and_build libosmo-abis
clone_and_build libosmo-netif
#clone_and_build asn1c aper-prefix-onto-upstream
clone_and_build libasn1c
clone_and_build libosmo-sccp old_sua
clone_and_build openggsn
clone_and_build libsmpp34
clone_and_build osmo-iuh
clone_and_build osmo-hlr
clone_and_build openbsc vlr_3G

set +x
echo "All done.

The next steps to get a 3G network running are outlined in ../README.txt
"
