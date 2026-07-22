#!/usr/bin/env bash
# hardbox installer
# Usage: curl -fsSL https://hardbox.jackby03.com/install.sh | bash
#
# Detects OS/arch, resolves release assets from GitHub API,
# verifies the SHA-256 checksum, and installs to /usr/local/bin/hardbox.
#
# Requirements: curl, tar, grep, awk, sed, sha256sum (or shasum)
# Supported:    Linux amd64, Linux arm64
#
# Environment overrides:
#   HARDBOX_VERSION       install a specific tag (e.g. v0.1.0)
#   HARDBOX_INSTALL_DIR   install directory (default: /usr/local/bin)
#   HARDBOX_REPO          override GitHub repo owner/name (default: jackby03/hardbox)

set -euo pipefail

REPO="${HARDBOX_REPO:-jackby03/hardbox}"
INSTALL_DIR="${HARDBOX_INSTALL_DIR:-/usr/local/bin}"
VERSION="${HARDBOX_VERSION:-}"
API_BASE="https://api.github.com/repos/${REPO}"

info()  { printf '\033[34m[hardbox]\033[0m %s\n' "$*"; }
ok()    { printf '\033[32m[hardbox]\033[0m %s\n' "$*"; }
err()   { printf '\033[31m[hardbox]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }

need() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || err "'$cmd' is required but not found in PATH"
  done
}

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
    err "Checksum mismatch! Expected: $expected, got: $actual"
  fi
  ok "Checksum verified."
}

json_get_tag_name() {
  sed -n -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$1" | head -n1
}

json_find_asset_url() {
  local json_file="$1"
  local pattern="$2"
  grep -Eo 'https://[^"[:space:]]+' "$json_file" | grep -E "$pattern" | head -n1 || true
}

fetch_release_json() {
  local json_file="$1"
  local endpoint
  if [ -n "$VERSION" ]; then
    endpoint="${API_BASE}/releases/tags/${VERSION}"
  else
    endpoint="${API_BASE}/releases/latest"
  fi

  if ! curl -fsSL "$endpoint" -o "$json_file"; then
    if [ -n "$VERSION" ]; then
      err "Release for tag ${VERSION} not found. Publish a GitHub Release (not just a git tag) and attach Linux binaries."
    fi
    err "Could not determine latest release. If you want a pre-release, set HARDBOX_VERSION=vX.Y.Z first."
  fi
}

main() {
  need curl tar grep awk sed

  local os arch
  os=$(detect_os)
  arch=$(detect_arch)

  local tmpdir release_json
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  release_json="${tmpdir}/release.json"

  if [ -z "$VERSION" ]; then
    info "Fetching latest stable release..."
  else
    info "Fetching release metadata for ${VERSION}..."
  fi
  fetch_release_json "$release_json"

  if [ -z "$VERSION" ]; then
    VERSION=$(json_get_tag_name "$release_json")
    [ -n "$VERSION" ] || err "Could not parse release tag from GitHub API response."
  fi

  local archive_url checksum_url archive_name checksum_file
  archive_url=$(json_find_asset_url "$release_json" "_${os}_${arch}\\.tar\\.gz$")
  checksum_url=$(json_find_asset_url "$release_json" "checksums\\.txt$")

  [ -n "$archive_url" ] || err "No ${os}/${arch} tar.gz asset found for ${VERSION}. Ensure release assets are published for this architecture."
  [ -n "$checksum_url" ] || err "No checksums.txt asset found for ${VERSION}."

  archive_name="$(basename "$archive_url")"
  checksum_file="$(basename "$checksum_url")"

  info "Installing hardbox ${VERSION} (${os}/${arch})"
  info "Download: ${archive_url}"

  info "Downloading archive..."
  curl -fsSL --progress-bar "$archive_url" -o "${tmpdir}/${archive_name}"

  info "Downloading checksums..."
  curl -fsSL "$checksum_url" -o "${tmpdir}/${checksum_file}"

  info "Verifying checksum..."
  local expected
  expected=$(grep "${archive_name}" "${tmpdir}/${checksum_file}" | awk '{print $1}' | head -n1)
  [ -n "$expected" ] || err "Could not find checksum entry for ${archive_name} in ${checksum_file}."
  verify_checksum "${tmpdir}/${archive_name}" "$expected"

  info "Extracting..."
  tar -xzf "${tmpdir}/${archive_name}" -C "$tmpdir"

  local binary="${tmpdir}/hardbox"
  [ -f "$binary" ] || err "Binary not found in archive. Expected ${binary}."
  chmod +x "$binary"

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
