#!/usr/bin/env bash
# hardbox installer
# Usage: curl -sSL https://hardbox.jackby03.com/install.sh | bash
#
# Detects OS/arch, downloads the latest release from GitHub,
# verifies the SHA-256 checksum, and installs to /usr/local/bin/hardbox.
#
# Requirements: curl, tar, sha256sum (or shasum on macOS)
# Supported:    Linux amd64, Linux arm64
#
# Environment overrides:
#   HARDBOX_VERSION   — install a specific version tag (e.g. v0.1.0)
#   HARDBOX_INSTALL_DIR — override install directory (default: /usr/local/bin)

set -euo pipefail

REPO="jackby03/hardbox"
INSTALL_DIR="${HARDBOX_INSTALL_DIR:-/usr/local/bin}"
VERSION="${HARDBOX_VERSION:-}"

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { printf '\033[34m[hardbox]\033[0m %s\n' "$*"; }
ok()    { printf '\033[32m[hardbox]\033[0m %s\n' "$*"; }
err()   { printf '\033[31m[hardbox]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }

need() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || err "'$cmd' is required but not found in PATH"
  done
}

# ── platform detection ────────────────────────────────────────────────────────
detect_os() {
  case "$(uname -s)" in
    Linux)  echo "linux" ;;
    *)      err "Unsupported OS: $(uname -s). hardbox requires Linux." ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo "amd64" ;;
    aarch64|arm64)  echo "arm64" ;;
    *)              err "Unsupported architecture: $(uname -m). Supported: amd64, arm64." ;;
  esac
}

# ── checksum verification ─────────────────────────────────────────────────────
verify_checksum() {
  local file="$1" expected="$2"
  local actual

  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    err "Neither sha256sum nor shasum found. Cannot verify checksum."
  fi

  if [ "$actual" != "$expected" ]; then
    err "Checksum mismatch!\n  Expected: $expected\n  Got:      $actual"
  fi
  ok "Checksum verified."
}

# ── latest version lookup ─────────────────────────────────────────────────────
latest_version() {
  local version
  version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
  [ -n "$version" ] || err "Could not determine latest hardbox version. Set HARDBOX_VERSION to override."
  echo "$version"
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
  need curl tar

  local os arch
  os=$(detect_os)
  arch=$(detect_arch)

  if [ -z "$VERSION" ]; then
    info "Fetching latest release..."
    VERSION=$(latest_version)
  fi

  local ver_clean="${VERSION#v}"   # strip leading 'v' for filename
  local archive="hardbox_${ver_clean}_${os}_${arch}.tar.gz"
  local base_url="https://github.com/${REPO}/releases/download/${VERSION}"
  local checksum_file="hardbox_${ver_clean}_checksums.txt"

  info "Installing hardbox ${VERSION} (${os}/${arch})"
  info "Download: ${base_url}/${archive}"

  # ── download to temp dir ──────────────────────────────────────────────────
  local tmpdir
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  info "Downloading archive..."
  curl -fsSL --progress-bar "${base_url}/${archive}" -o "${tmpdir}/${archive}"

  info "Downloading checksums..."
  curl -fsSL "${base_url}/${checksum_file}" -o "${tmpdir}/${checksum_file}"

  # ── verify checksum ───────────────────────────────────────────────────────
  info "Verifying checksum..."
  local expected
  expected=$(grep "${archive}" "${tmpdir}/${checksum_file}" | awk '{print $1}')
  [ -n "$expected" ] || err "Could not find checksum for ${archive} in ${checksum_file}"
  verify_checksum "${tmpdir}/${archive}" "$expected"

  # ── extract + install ─────────────────────────────────────────────────────
  info "Extracting..."
  tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"

  local binary="${tmpdir}/hardbox"
  [ -f "$binary" ] || err "Binary not found in archive. Expected: ${tmpdir}/hardbox"
  chmod +x "$binary"

  # ── place binary ──────────────────────────────────────────────────────────
  if [ -w "$INSTALL_DIR" ]; then
    mv "$binary" "${INSTALL_DIR}/hardbox"
  else
    info "Sudo required to write to ${INSTALL_DIR}"
    sudo mv "$binary" "${INSTALL_DIR}/hardbox"
  fi

  ok "hardbox ${VERSION} installed to ${INSTALL_DIR}/hardbox"
  ok "Run: sudo hardbox audit --profile cis-level1"
  echo ""
  "${INSTALL_DIR}/hardbox" --version
}

main "$@"
