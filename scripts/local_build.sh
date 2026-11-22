#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: scripts/local_build.sh [options]
  --bundles deb,rpm,archlinux   Comma-separated formats (all three by default on x64)
  --mode auto|native|container  Auto uses native tools on a matching host
  --engine auto|podman|docker   Container engine (auto prefers Podman)
  --target TARGET               Native Linux GNU Rust target
  --go-version VERSION          Override the container Go toolchain
  --skip-tests                  Skip the frontend and Rust test suites
  --no-artifact                 Leave output in the Cargo target directory
  --no-cache                    Rebuild container layers
  --print-plan                  Show the selected builders without building
  --verbose                     Show build commands and output
HELP
}

die() {
    echo "$*" >&2
    exit 1
}
mode=auto
engine=auto
bundles=deb,rpm
[[ $(uname -m) != x86_64 ]] || bundles+=,archlinux
go_version=${VRG_GO_VERSION:-}
target=${CARGO_TARGET:-${CARGO_BUILD_TARGET:-}}
profile=${BUILD_CONFIGURATION:-Release}
skip_tests=0
stage=1
plan=0
verbose=0
image_args=()
while (($#)); do
    case "$1" in
        --mode | --engine | --bundles | --target | --go-version)
            (($# >= 2)) || die "Missing value for $1"
            option="$1=$2"
            shift
            ;;
        *) option=$1 ;;
    esac
    case "$option" in
        --mode=*) mode=${option#*=} ;;
        --engine=*) engine=${option#*=} ;;
        --bundles=*) bundles=${option#*=} ;;
        --target=*) target=${option#*=} ;;
        --go-version=*) go_version=${option#*=} ;;
        --skip-tests) skip_tests=1 ;;
        --no-artifact) stage=0 ;;
        --no-cache) image_args+=(--no-cache) ;;
        --print-plan) plan=1 ;;
        --verbose) verbose=1 ;;
        -h | --help)
            usage
            exit
            ;;
        *) die "Unknown option: $option" ;;
    esac
    shift
done
case "$mode" in auto | native | container) ;; *) die "Unknown mode: $mode" ;; esac
case "$engine" in auto | podman | docker) ;; *) die "Unknown engine: $engine" ;; esac
case "$profile" in
    Release)
        cargo_profile=release
        directory=release
        ;;
    Debug)
        cargo_profile=dev
        directory=debug
        ;;
    *) die "Unsupported build configuration: $profile" ;;
esac
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ $(uname -s) == Linux ]] || die "Linux is required"
arch=$(uname -m)
case "$arch" in
    x86_64) export PACKAGE_ARCH=amd64 ;;
    aarch64) export PACKAGE_ARCH=arm64 ;;
    *) die "Unsupported architecture: $arch" ;;
esac
# The Go bridge is built with the native C compiler.
[[ ${target:-$arch-unknown-linux-gnu} == "$arch-unknown-linux-gnu" ]] || die "Expected native target $arch-unknown-linux-gnu"
# shellcheck source=/dev/null
source /etc/os-release
case " $ID ${ID_LIKE:-} " in
    *' arch '*) family=archlinux ;;
    *' debian '*) family=deb ;;
    *' rhel '* | *' fedora '* | *' centos '*) family=rpm ;;
    *) family=unknown ;;
esac
native_tools() {
    local tool
    for tool in nfpm cargo rustc go bun node gcc pkg-config; do
        command -v "$tool" >/dev/null || return 1
    done
    pkg-config --exists gtk+-3.0 webkit2gtk-4.1 dbus-1
}

build_native() {
    local format=$1
    local -a target_args=()
    local target_dir
    target_dir=$(cargo metadata --no-deps --locked --format-version 1 | bun -p '(await Bun.stdin.json()).target_directory')
    if [[ -n $target ]]; then
        target_args=(--target "$target")
        target_dir+="/$target"
    fi
    export GOTOOLCHAIN=local
    bun install --frozen-lockfile
    bun run build
    bun run check
    cargo fmt --all -- --check
    cargo check --locked --all-targets --all-features "${target_args[@]}"
    cargo clippy --locked --all-targets --all-features "${target_args[@]}" -- -D warnings
    if ((! skip_tests)); then
        bun test frontend
        cargo test --locked --all-targets --all-features "${target_args[@]}"
    fi
    cargo build --locked --bins --features custom-protocol --profile "$cargo_profile" "${target_args[@]}"
    export BINARY_DIR="$target_dir/$directory"
    local version package_dir
    version=$(bun -p "Bun.TOML.parse(await Bun.file('Cargo.toml').text()).package.version")
    export PACKAGE_VERSION="$version"
    package_dir="$BINARY_DIR/bundle/$format"
    mkdir -p "$package_dir"
    tmp_dir=$(mktemp -d "$package_dir/.nfpm.XXXXXX")
    trap 'rm -rf -- "$tmp_dir"' EXIT
    nfpm package --config packaging/nfpm.yaml --packager "$format" --target "$tmp_dir/"
    local -a packages=("$tmp_dir"/*)
    [[ ${#packages[@]} == 1 && -s ${packages[0]} ]] || die "Expected one $format package"
    mv -f "${packages[0]}" "$package_dir/"
    if ((stage)); then
        mkdir -p artifacts
        cp "$package_dir/${packages[0]##*/}" artifacts/
        echo "Staged artifacts/${packages[0]##*/}"
    fi
    rmdir "$tmp_dir"
    trap - EXIT
}

build_container() {
    local format=$1
    if [[ $engine == auto ]]; then
        if command -v podman >/dev/null; then engine=podman; else engine=docker; fi
    fi
    local -a build_args=("${image_args[@]}") run_args=() options=(--mode native --bundles "$format")
    [[ -z $go_version ]] || build_args+=(--build-arg "GO_VERSION=$go_version")
    [[ -z $target ]] || options+=(--target "$target")
    ((skip_tests == 0)) || options+=(--skip-tests)
    ((stage)) || options+=(--no-artifact)
    if [[ $engine == docker ]]; then run_args+=(--user "$(id -u):$(id -g)"); fi
    mkdir -p .buildcache/home
    local image="vrghotspot-build-$format:local"
    "$engine" build "${build_args[@]}" --build-arg "FORMAT=$format" -t "$image" packaging
    "$engine" run --rm "${run_args[@]}" -v "$PWD:/work:z" -w /work \
        -e HOME=/work/.buildcache/home -e CARGO_HOME=/work/.buildcache/cargo \
        -e "CARGO_TARGET_DIR=/work/.container-target/$format" \
        -e GOCACHE=/work/.buildcache/go-build -e GOPATH=/work/.buildcache/go \
        -e "BUILD_CONFIGURATION=$profile" -e CARGO_PROFILE_DEV_DEBUG -e CARGO_INCREMENTAL \
        -e VRG_DEFAULT_SUBSCRIPTION_URL -e VRG_SUPPORT_ENDPOINT \
        "$image" bash scripts/local_build.sh "${options[@]}"
}

IFS=, read -ra formats <<<"$bundles"
for format in "${formats[@]}"; do
    case "$format" in deb | rpm | archlinux) ;; *) die "Unknown package format: $format" ;; esac
done
built=0
for format in "${formats[@]}"; do
    builder=$mode
    if [[ $mode == auto ]]; then
        builder=container
        if [[ $format == "$family" ]] && native_tools; then builder=native; fi
    elif [[ $mode == native && $format != "$family" ]]; then
        echo "Skipping $format on $ID"
        continue
    fi
    if [[ $format == archlinux && $builder == container && $arch != x86_64 ]]; then
        die "The Arch Linux container requires x86_64. Arch Linux ARM can build natively."
    fi
    echo "$format ($arch): $builder"
    if ((! plan)); then
        ((verbose == 0)) || set -x
        "build_$builder" "$format"
    fi
    built=1
done
((built)) || die "No matching package formats"
