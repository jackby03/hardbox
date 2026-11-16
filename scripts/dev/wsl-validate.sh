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
# wsl-validate.sh — run the Linux-only quality gates on a WSL-native copy of
# the repository.
#
# Why a native copy instead of /mnt/c: /mnt/c is mounted as 9p/drvfs without
# the "metadata" option, so chmod is masked and 0000-mode files stay readable.
# Any test that asserts Unix permission semantics therefore cannot be
# validated from /mnt/c. It must run on ext4.
#
# Usage (from Windows):
#   wsl -d Debian -- bash -lc '~/src/hardbox/scripts/dev/wsl-validate.sh'
#
# Usage (from WSL):
#   bash scripts/dev/wsl-validate.sh [--src DIR] [--work DIR] [--no-sync]

set -euo pipefail

# Hermetic PATH: never inherit the Windows interop PATH. It contains a Windows
# Go toolchain under /mnt/c, and picking that up silently yields host-OS
# results (windows/386) instead of linux/amd64.
export PATH="${HOME}/.local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/lib/wsl/lib"
export CGO_ENABLED=1

SRC="/mnt/c/Users/jackd/Development/hardbox"
WORK="${HOME}/src/hardbox"
SYNC=1

while [ $# -gt 0 ]; do
  case "$1" in
    --src)   SRC="$2";  shift 2 ;;
    --work)  WORK="$2"; shift 2 ;;
    --no-sync) SYNC=0;  shift ;;
    -h|--help) sed -n '22,33p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

command -v go >/dev/null 2>&1 || {
  echo "error: go not found. Run scripts/dev/wsl-setup.sh first." >&2
  exit 1
}

echo "== host =="
printf '  go      : %s\n' "$(go version)"
printf '  platform: %s/%s cgo=%s\n' "$(go env GOOS)" "$(go env GOARCH)" "$(go env CGO_ENABLED)"
printf '  workdir : %s (%s)\n' "$WORK" "$(df -h "$WORK" 2>/dev/null | awk 'NR==2{print $1}')"

if [ "$SYNC" -eq 1 ]; then
  [ -d "$WORK" ] || mkdir -p "$WORK"
  echo
  echo "== sync =="
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude '.git' --exclude 'bin' --exclude 'dist' \
      "${SRC}/" "${WORK}/"
  else
    find "$WORK" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    ( cd "$SRC" && tar --exclude=.git --exclude=bin --exclude=dist -cf - . ) \
      | ( cd "$WORK" && tar -xf - )
  fi
  echo "  synced ${SRC} -> ${WORK}"
fi

cd "$WORK"

fail=0
run() {
  local label="$1"; shift
  echo
  echo "== ${label} =="
  if "$@"; then
    echo "  PASS"
  else
    echo "  FAIL"
    fail=1
  fi
}

run "build" go build ./...
run "vet"   go vet ./...
run "test -race" go test ./... -race -count=1

echo
if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
