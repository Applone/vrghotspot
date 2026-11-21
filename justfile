linux_flags := if os() == "linux" { "" } else { "--target x86_64-unknown-linux-gnu" }
windows_flags := "--target x86_64-pc-windows-gnu"

[arg("target", pattern="linux|windows")]
check target="linux": frontend
    bun run check
    cargo fmt --all -- --check
    cargo check --locked --all-targets --all-features {{ if target == "linux" { linux_flags } else { windows_flags } }}
    cargo clippy --locked --all-targets --all-features {{ if target == "linux" { linux_flags } else { windows_flags } }} -- -D warnings

test: frontend
    bun test frontend
    cargo test --locked --all-targets --all-features

[arg("target", pattern="linux|windows")]
build target="linux": frontend
    cargo build --locked --release --features custom-protocol {{ if target == "linux" { linux_flags } else { windows_flags } }}

# Build ready-to-install packages in artifacts/.
[arg("format", pattern="all|deb|rpm|arch|win")]
bundle format="all":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ format }}" in
        all)  bash scripts/local_build.sh --bundles deb,rpm,archlinux
              bash scripts/package-windows.sh ;;
        arch) bash scripts/local_build.sh --bundles archlinux ;;
        win)  bash scripts/package-windows.sh ;;
        *)    bash scripts/local_build.sh --bundles "{{ format }}" ;;
    esac

[private]
frontend:
    bun run build
