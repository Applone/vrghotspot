ARG FORMAT=deb
ARG GO_VERSION=1.27.3
FROM docker.io/library/golang:${GO_VERSION}-bookworm AS golang
FROM docker.io/library/rust:1.99.1-bookworm AS rust
RUN rustup component add clippy rustfmt
FROM docker.io/library/node:26-bookworm-slim AS node
FROM docker.io/oven/bun:1.4.4 AS bun
FROM ghcr.io/goreleaser/nfpm:v2.49.0 AS nfpm

FROM docker.io/library/debian:13-slim AS deb-runtime
FROM docker.io/library/almalinux:10 AS rpm-runtime
RUN dnf -y install dnf-plugins-core epel-release && dnf config-manager --set-enabled crb
FROM docker.io/library/archlinux:base AS archlinux-runtime

FROM deb-runtime AS deb
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates git libdbus-1-dev libgtk-3-dev libssl-dev \
    libwebkit2gtk-4.1-dev pkg-config && rm -rf /var/lib/apt/lists/*

FROM rpm-runtime AS rpm
RUN dnf -y install gcc gcc-c++ git make pkgconf-pkg-config dbus-devel \
    gtk3-devel openssl-devel webkit2gtk4.1-devel && dnf clean all

FROM archlinux-runtime AS archlinux
RUN pacman -Syu --noconfirm --needed base-devel git gtk3 webkit2gtk-4.1

FROM ${FORMAT} AS builder
COPY --from=golang /usr/local/go /usr/local/go
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo/bin/ /usr/local/bin/
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY --from=nfpm /usr/bin/nfpm /usr/local/bin/nfpm
ENV RUSTUP_HOME=/usr/local/rustup GOTOOLCHAIN=local PATH=/usr/local/go/bin:${PATH}
WORKDIR /work
