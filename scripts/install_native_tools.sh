#!/usr/bin/env bash
# CI-only Linux installer. Sources retain their own licenses; nothing is vendored.
set -euo pipefail
: "${RUNNER_TEMP:?Run on a disposable CI runner with RUNNER_TEMP set}"
sudo apt-get update
sudo apt-get install -y --no-install-recommends klayout build-essential cmake ninja-build tcl-dev swig bison flex libeigen3-dev libfmt-dev zlib1g-dev autoconf automake libtool
prefix="$RUNNER_TEMP/opentapeout-native"
mkdir -p "$prefix/src"
fetch_pin() {
  local url="$1" revision="$2" dest="$3"
  git init "$dest"
  git -C "$dest" remote add origin "$url"
  git -C "$dest" fetch --depth=1 origin "$revision"
  git -C "$dest" checkout --detach FETCH_HEAD
  test "$(git -C "$dest" rev-parse HEAD)" = "$revision"
}
fetch_pin https://github.com/cuddorg/cudd.git f54f533303640afd5dbe47a05ebeabb3066f2a25 "$prefix/src/cudd"
(
  cd "$prefix/src/cudd"
  autoreconf -fi
  ./configure --prefix="$prefix/cudd" --enable-silent-rules
  make -j2
  make install
)
fetch_pin https://github.com/parallaxsw/OpenSTA.git 2996e37a3aa7fdfd197b84842df719e70757657f "$prefix/src/OpenSTA"
cmake -S "$prefix/src/OpenSTA" -B "$prefix/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCUDD_DIR="$prefix/cudd"
cmake --build "$prefix/build" -j2
mkdir -p "$prefix/bin"
cp "$prefix/build/sta" "$prefix/bin/sta"
echo "$prefix/bin" >> "$GITHUB_PATH"
