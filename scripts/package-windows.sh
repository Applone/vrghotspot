#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
case "${BUILD_CONFIGURATION:-Release}" in
    Release)
        profile=release
        options=()
        ;;
    Debug)
        profile=debug
        options=(--debug)
        ;;
    *)
        echo "Expected Debug or Release" >&2
        exit 1
        ;;
esac
target=x86_64-pc-windows-gnu
options+=(--target "$target")
bun run tauri build "${options[@]}" --no-bundle -- --locked
# MinGW links WebView2Loader.dll dynamically. Resolve the just-built DLL for
# this profile and install it alongside the executable.
target_dir=$(cargo metadata --format-version 1 --no-deps --locked | bun -p '(await Bun.stdin.json()).target_directory')
config=$(bun -p 'JSON.stringify({bundle:{resources:{[process.argv[1]]:"WebView2Loader.dll"}}})' "$target_dir/$target/$profile/WebView2Loader.dll")
bun run tauri bundle "${options[@]}" --bundles nsis --config "$config"
installer=$(bun -p 'const {productName, version} = await Bun.file("tauri.conf.json").json(); productName + "_" + version + "_x64-setup.exe"')
mkdir -p artifacts
cp "$target_dir/$target/$profile/bundle/nsis/$installer" artifacts/
