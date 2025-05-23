#!/usr/bin/env bash

set -euo pipefail
set -x

cd "$(dirname "$0")" || exit 1
RUNTIME_VERSION=$(npm pkg get version --json --prefix=../../ | jq -r)
HOST_API=$(realpath host-api) cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug -DENABLE_BUILTIN_WEB_FETCH=0 -DENABLE_BUILTIN_WEB_FETCH_FETCH_EVENT=0 -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DRUNTIME_VERSION="\"$RUNTIME_VERSION-debug\"" -DENABLE_JS_DEBUGGER=OFF
cmake --build build-debug --parallel 10
if [ "${1:-default}" != "--keep-debug-info" ]; then
  wasm-tools strip build-debug/starling-raw.wasm/starling-raw.wasm -d ".debug_(info|loc|ranges|abbrev|line|str)" -o ../../fastly.debug.wasm
else
  cp build-debug/starling-raw.wasm/starling-raw.wasm ../../fastly.debug.wasm
fi
