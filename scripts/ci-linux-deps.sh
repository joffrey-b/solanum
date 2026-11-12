#!/usr/bin/env bash
# Installs what a Linux CI job needs to compile and test Solanum: the WebKitGTK / GTK development
# packages Tauri links against. Options:
#   --bundle   also install the tools that build .deb / .rpm / AppImage packages
#   --node     also require Node.js 22.12 or newer. This only checks: Node comes from the runner
#              (installed by hand on a shell executor, actions/setup-node on GitHub), and it fails
#              here with a clear message instead of later with a confusing one
#
# Installing needs root or passwordless sudo. Without either it changes nothing and assumes the runner
# already has these installed (typical for a shell-executor runner that was set up by hand).
set -euo pipefail

bundle=0 node=0
for arg in "$@"; do
  case "$arg" in
    --bundle) bundle=1 ;;
    --node)   node=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ "$node" = 1 ]; then
  if ! node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 12) ? 0 : 1)' 2>/dev/null; then
    echo "ci-linux-deps: Node.js 22.12 or newer is required (found: $(node --version 2>/dev/null || echo none)). Install it on the runner." >&2
    exit 1
  fi
fi

SUDO=""
if [ "$(id -u)" != "0" ]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO="sudo"
  else
    echo "ci-linux-deps: not root and no passwordless sudo — assuming the build dependencies are already installed."
    exit 0
  fi
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "ci-linux-deps: no apt-get on this system — assuming the build dependencies are already installed."
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive
packages=(
  build-essential pkg-config ca-certificates
  libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
  libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libssl-dev
)
if [ "$bundle" = 1 ]; then
  packages+=(patchelf file rpm xdg-utils)
fi

$SUDO apt-get update -qq
$SUDO apt-get install -y -qq --no-install-recommends "${packages[@]}"

echo "ci-linux-deps: done."
