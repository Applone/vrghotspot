# VRG Hotspot

VRG Hotspot shares an embedded Mihomo VPN over Wi-Fi. Windows and Linux use the
same Svelte 5/Tauri interface for VPN profiles, hotspot credentials, the connection
status, logs, and support reports.

## Using the app

Use **+** on the home screen to paste an HTTPS subscription URL or a Mihomo
YAML proxy configuration from the clipboard. A Clash/Mihomo YAML document with
a `proxies` list imports each usable node as a local profile. Choose **Ручной
ввод** to create a profile in the YAML editor. Select a profile on the home
screen or choose **Прямое подключение** for direct routing. The arrow on each
profile opens its YAML. Local edits to subscription profiles survive refresh
while the provider still offers the node.

Each subscription has its own refresh and TCP ping controls. In its **…** menu,
you can change the title, URL, refresh interval, and HWID setting, or delete the
subscription and its profiles. Auto-refresh and HWID are off by default. When
enabled, HWID sends a persistent installation ID to the provider.

Enter a Wi-Fi network name and password, then start from the home screen.
Use the gear icon to open Settings and disable internet sharing for VPN on the
host only. The home screen shows missing Wi-Fi adapters. Connecting an adapter
restores hotspot availability and keeps the saved sharing mode.

- **Linux** uses NetworkManager, nftables, and polkit. Single-radio Wi-Fi uplinks
  can also require `hostapd`, `dnsmasq`, and `iw`. To create the Mihomo TUN as
  your desktop user, grant the installed executable
  `sudo setcap cap_net_admin,cap_net_raw+eip /usr/bin/vrghotspot` after installation.
- **Windows** needs x64 Windows 10 version 2004 or later, WebView2, a Wi-Fi
  adapter with Mobile Hotspot support, and an internet uplink. Accept the
  Administrator prompt when opening the app. Turn off any existing Windows
  Mobile Hotspot before starting VRG Hotspot. Mihomo carries its Wintun driver.
  Windows Mobile Hotspot and the verified private ICS API connect the Wi-Fi
  Direct adapter to the app's Wintun device. A sharing setup error is shown in
  the app while the host VPN remains active.
  Leave **Settings → Hotspot adapter** (**Настройки → Адаптер точки доступа**)
  on **Автоматически** for normal use. To use a specific Wi-Fi radio, select its
  model and Windows interface name if Windows exposes a connection profile for it.
  If automatic selection reports several Wi-Fi Direct interfaces, stop the connection.
  You can briefly turn on Windows Mobile Hotspot and match an active interface's
  IPv4 address in Settings to the gateway shown on a connected device. Save the
  selection and turn off Windows Mobile Hotspot before starting VRG Hotspot.

### Windows sharing compatibility

Private ICS calls require a reviewed x64 System32 `hnetcfgclient.dll` build.

| Build | DLL SHA-256 |
| --- | --- |
| Windows 11 reference | `1bdccc9dabadbf372bf1a81f42aab8a4bdb48a221d816d48352b94a624f71794` |
| Windows 10 10.0.19041.4355 | `275b3bd71a918582169d3738ccf0816150c4e33e2bb492eb53d3157f769c2499` |

An unmatched DLL disables Windows Wi-Fi sharing. The check runs before
changing Mobile Hotspot settings. The native code verifies the DLL hash, its
PE signatures at x64 function boundaries, COM registration, the loaded
methods, and the resulting interface indexes. Supporting another DLL build
requires reviewing its private ABI.

### Windows compatibility reports

A failed check of the private Windows Internet Connection Sharing (ICS) APIs
offers a one-time report. The report contains the checked System32
`hnetcfgclient.dll`, its SHA-256 checksum, the verification result, and the
Windows build and update revision when available. You can inspect the report
before confirming the upload. After the upload, copy the report ID to share
with support.

Build Windows releases with `VRG_SUPPORT_ENDPOINT` set to the HTTPS base URL of
the Go telemetry receiver. The app posts to `v1/reports` below that base URL.
For local testing, the base URL may use HTTP with a loopback IP address.

## Build and verify

Install current stable Rust, Go 1.26 or newer, Bun, and a C toolchain. The
Mihomo source is pinned as a Git submodule in `src/third_party/mihomo`.
Clone with `git clone --recurse-submodules`, or run
`git submodule update --init --recursive` from an existing checkout before building.

On Linux, install GTK 3, WebKit2GTK 4.1, pkg-config, and the Tauri development
libraries for your distribution. Then run:

```sh
bun install --frozen-lockfile
just check
just test
just build
bun run tauri dev
```

`just check` runs Svelte type and compiler checks and Biome lint and formatting checks,
then runs Rust formatting, type checks, and Clippy. `just test` runs the
frontend, Rust unit, and CLI integration tests. `just build`
embeds the production frontend. Both `just check` and `just build` default to
`linux` and accept an explicit `linux` or `windows` argument.

For a standalone Cargo build, run `bun run build` before `cargo build --locked`
or `cargo run --locked`. The default Cargo build embeds the frontend. The
executable produced by `bun run tauri dev` requires its Vite server on
`127.0.0.1:1420` for as long as it is running.

### Distribution packages

CI builds four x64 installers. Branch pushes and pull requests build Debug
packages. A `v<version>` tag builds Release packages, checks installation, and
publishes the tested artifacts with SHA-256 checksums.

| Target | Artifact | Local install |
| --- | --- | --- |
| Debian 13 | `.deb` | `sudo apt install ./vrghotspot_*.deb` |
| RHEL 10 and compatible distributions | `.rpm` | `sudo dnf install ./vrghotspot-*.rpm` |
| Arch Linux and derivatives | `.pkg.tar.zst` | `sudo pacman -U ./vrghotspot-*.pkg.tar.zst` |
| Windows 10/11 x64 | NSIS `-setup.exe` | Run the installer |

The RPM is built on AlmaLinux 10. Enable EPEL 10 and the corresponding
CodeReady Builder (CRB) repository for its WebKitGTK dependencies.
After installing a Linux package, apply the TUN capability described under
**Using the app**.

On x64 Linux, `just bundle` builds all four installers into `artifacts/`.
Use `just bundle deb`, `rpm`, `arch`, or `win` to build one. Windows cross-bundling
requires MinGW-w64, the Windows GNU Rust target, and NSIS (`makensis`).

On x64 Linux, run `bash scripts/local_build.sh --mode container` to build all three
packages with nFPM in their distribution environments. This needs Podman or
Docker. For a host-native package, install nFPM and the development
dependencies above and run `bash scripts/local_build.sh --mode native`.
The default mode chooses native or container per format. Pass
`--bundles archlinux`, `deb`, or `rpm` to select one. Packages are written to
`artifacts/`. Native builds link against the host libraries.

On Windows, put Git Bash and the x64 MinGW-w64 toolchain on PATH. Use the Rust GNU target to
link the embedded Go archive:

```powershell
rustup target add x86_64-pc-windows-gnu
bun install --frozen-lockfile
bun run build
cargo test --locked --all-features --all-targets --target x86_64-pc-windows-gnu
bash scripts/package-windows.sh
```

The NSIS installer is created under
`target/x86_64-pc-windows-gnu/release/bundle/nsis/`. From Linux with MinGW and
the same Rust target installed, run `just check windows` and
`just build windows` to cross-check and build the executables.
The standalone Windows release executable is
`target/x86_64-pc-windows-gnu/release/vrghotspot.exe`.
Keep `WebView2Loader.dll` next to the executable when copying it without the
installer.

CI builds omit the default subscription by default. To bundle one, set the
repository secret `VRG_DEFAULT_SUBSCRIPTION_URL`. Enable **Bundle the optional
default VPN subscription** when dispatching the Debug workflow, or set the
repository variable `VRG_BUNDLE_SUBSCRIPTION` to `true` for release builds.
For local builds, set `VRG_DEFAULT_SUBSCRIPTION_URL` in the build environment.
Per-user settings and logs live in
`~/.config/vrghotspot` on Linux or `%APPDATA%\vrghotspot` on Windows.

## Diagnostics

Building with `--features cli` enables `vrghotspot cli adapters`,
`hotspot-status`, `net`, `tun-only`, `start`, and `stop`.

The original Windows diagnostics are available as `vrghotspot-diagnostics`.
Run `vrghotspot-diagnostics.exe --self-test` on x64 Windows to check Wi-Fi,
DLL exports, signatures, and COM registration. Offline PE scanning is also
available on Linux:

```sh
cargo run --locked --bin vrghotspot-diagnostics -- --scan-only --dll-path /path/to/hnetcfgclient.dll
```

The advanced `--apply` and `--hotspot-tun` diagnostic modes require
Administrator privileges and change system sharing state. `--apply` replaces
the existing ICS pair. `--hotspot-tun` expects an active TUN, starts Windows
Mobile Hotspot, and changes persistent IPv4 interface settings. Run
`--help` for the argument list.

To verify routing on either platform, connect a separate device to the
hotspot, check that its egress uses the selected VPN, then stop the hotspot
and confirm the host's normal connection is restored.
