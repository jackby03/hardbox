#!/usr/bin/env bash
# Copyright (C) 2024 Jack (jackby03)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# wsl-setup.sh — provision the Go toolchain inside WSL so Linux-only gates
# (go test -race) can run locally. Idempotent; no sudo required.
#
# Usage (from WSL):  bash scripts/dev/wsl-setup.sh [go-version]
# Usage (from Windows): wsl -d Debian -- bash -lc 'cd ~/src/hardbox && bash scripts/dev/wsl-setup.sh'

set -euo pipefail

VERSION="${1:-go1.27.4}"
DEST="${HOME}/.local"
TARBALL="${TMPDIR:-/tmp}/${VERSION}.linux-amd64.tar.gz"

echo "== hardbox: WSL toolchain setup =="
echo "target version: ${VERSION}"
echo "install prefix: ${DEST}/go"

if "${DEST}/go/bin/go" version 2>/dev/null | grep -q "${VERSION#go}"; then
  echo "already installed: $("${DEST}/go/bin/go" version)"
  exit 0
fi

mkdir -p "${DEST}"

if [ ! -f "${TARBALL}" ]; then
  echo "downloading ${VERSION}.linux-amd64.tar.gz ..."
  curl -fsSL --retry 3 -o "${TARBALL}" \
    "https://dl.google.com/go/${VERSION}.linux-amd64.tar.gz"
fi

echo "extracting ..."
rm -rf "${DEST}/go"
tar -C "${DEST}" -xzf "${TARBALL}"

if ! grep -q '\.local/go/bin' "${HOME}/.bashrc" 2>/dev/null; then
  printf '\nexport PATH="$HOME/.local/go/bin:$PATH"\n' >> "${HOME}/.bashrc"
  echo "added ~/.local/go/bin to ~/.bashrc"
fi

echo "installed: $("${DEST}/go/bin/go" version)"
