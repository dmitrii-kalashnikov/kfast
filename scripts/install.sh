#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-dmitrii-kalashnikov/kfast}" 
BIN="${BIN:-kfast}"
TAG="${TAG:-}"
PREFIX="${PREFIX:-/usr/local}"
INSTALL_KUBECTL="${INSTALL_KUBECTL:-1}"

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# --- OS/ARCH normalize ---
OS="$(uname | tr '[:upper:]' '[:lower:]')"   # linux or darwin
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac
case "$OS" in
  linux|darwin) ;;
  msys*|cygwin*|mingw*) echo "Use install.ps1 on Windows."; exit 1 ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# --- SHA256 verify helper ---
verify_sha256() {
  local file="$1" expected="$2"
  if has_cmd sha256sum; then
    echo "${expected}  ${file}" | sha256sum -c -
  elif has_cmd shasum; then
    echo "${expected}  ${file}" | shasum -a 256 -c -
  elif has_cmd openssl; then
    local got; got=$(openssl dgst -sha256 "${file}" | awk '{print $2}')
    [[ "${got}" == "${expected}" ]] || { echo "Checksum mismatch for ${file}"; exit 1; }
  else
    echo "No SHA256 tool found; skipping checksum verification."
  fi
}

# --- GitHub API (handles GH_TOKEN) ---
ghcurl() {
  local url="$1"
  if [[ -n "${GH_TOKEN:-}" ]]; then
    curl -fsSL -H "Authorization: Bearer ${GH_TOKEN}" -H "Accept: application/vnd.github+json" "$url"
  else
    curl -fsSL -H "Accept: application/vnd.github+json" "$url"
  fi
}

# --- tag resolution ---
if [[ -z "${TAG}" ]]; then
  TAG="$(ghcurl "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep -oE '"tag_name":\s*"[^"]+' | cut -d'"' -f4)"
  [[ -n "$TAG" ]] || { echo "Cannot resolve latest release tag for ${REPO}"; exit 1; }
fi

ASSET="${BIN}_${OS}_${ARCH}"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}.tar.gz"
CHK_URL="https://github.com/${REPO}/releases/download/${TAG}/checksums.txt"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "⬇️  Downloading ${URL}"
curl -fsSL "${URL}" -o "${TMP}/${ASSET}.tar.gz" || { echo "Asset not found. Ensure your release has ${ASSET}.tar.gz"; exit 1; }

echo "⬇️  Downloading checksums"
curl -fsSL "${CHK_URL}" -o "${TMP}/checksums.txt" || echo "No checksums.txt found (skipping verification)."

if [[ -s "${TMP}/checksums.txt" ]]; then
  ARCHIVE_SHA=$(grep " ${ASSET}.tar.gz\$" "${TMP}/checksums.txt" | awk '{print $1}' || true)
  if [[ -n "${ARCHIVE_SHA}" ]]; then
    verify_sha256 "${TMP}/${ASSET}.tar.gz" "${ARCHIVE_SHA}"
  else
    echo "checksums.txt does not contain ${ASSET}.tar.gz; skipping verification."
  fi
fi

tar -C "${TMP}" -xzf "${TMP}/${ASSET}.tar.gz"

# choose install dest (prefer Homebrew prefix if present on macOS)
DEST="${PREFIX}/bin"
if [[ "$OS" == "darwin" && -d "/opt/homebrew/bin" ]]; then
  DEST="/opt/homebrew/bin"
fi
if [[ ! -w "${DEST}" ]]; then
  DEST="${HOME}/.local/bin"
  mkdir -p "${DEST}"
  if ! echo "$PATH" | grep -q "${HOME}/.local/bin"; then
    for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
      [[ -f "$rc" ]] && { echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"; break; }
    done
    export PATH="$HOME/.local/bin:$PATH"
  fi
fi

install -m 0755 "${TMP}/${BIN}" "${DEST}/${BIN}"
echo "✅ Installed ${BIN} to ${DEST}/${BIN}"

if [[ "${INSTALL_KUBECTL}" == "1" && ! has_cmd kubectl ]]; then
  echo "ℹ️  kubectl not found; installing a stable kubectl locally..."
  KVER="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
  KURL="https://dl.k8s.io/release/${KVER}/bin/${OS}/${ARCH}/kubectl"
  KCHK="https://dl.k8s.io/${KVER}/bin/${OS}/${ARCH}/kubectl.sha256"
  curl -fsSL "${KURL}" -o "${TMP}/kubectl"
  curl -fsSL "${KCHK}" -o "${TMP}/kubectl.sha256"
  verify_sha256 "${TMP}/kubectl" "$(cat "${TMP}/kubectl.sha256")"
  chmod +x "${TMP}/kubectl"
  install -m 0755 "${TMP}/kubectl" "${DEST}/kubectl"
  echo "✅ Installed kubectl to ${DEST}/kubectl"
fi

echo "🎉 Done. Try: ${BIN} --help"
