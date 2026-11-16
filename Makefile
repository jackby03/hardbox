.PHONY: build run test test-race validate lint fmt vet audit dry-run release snapshot clean

BINARY := hardbox
CMD     := ./cmd/hardbox
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-X main.version=$(VERSION)"

# hardbox ships as a static, distro-agnostic binary: never link libc.
BUILD_ENV := CGO_ENABLED=0

# ── Build ────────────────────────────────────────────────────────────────────

build:
	$(BUILD_ENV) go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

run: build
	sudo ./bin/$(BINARY)

install: build
	sudo install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

# ── Development ──────────────────────────────────────────────────────────────

# Fast, cross-platform suite. Platform-dependent assertions opt out via the
# guards in internal/modules/util/testutil/platform.go.
test:
	go test ./... -count=1

# Race detector. Requires cgo and an architecture the detector supports, so it
# cannot run on windows/386 or with CGO_ENABLED=0. This is the gate CI enforces.
test-race:
	@if [ "$$(go env GOARCH)" = "386" ]; then \
		echo "error: -race is not supported on $(shell go env GOOS)/386." >&2; \
		echo "       Use a 64-bit toolchain, or validate on Linux instead." >&2; \
		exit 1; \
	fi; \
	if [ "$$(go env CGO_ENABLED)" != "1" ]; then \
		echo "error: -race requires cgo." >&2; \
		echo "       Retry with CGO_ENABLED=1, or validate on Linux instead." >&2; \
		exit 1; \
	fi
	CGO_ENABLED=1 go test ./... -race -count=1

# Everything CI runs for a pull request, in the same order.
validate: build vet test-race

# Windows note: /mnt/c is mounted over 9p without the 'metadata' option, so POSIX
# permission bits are masked and chmod-based tests cannot be trusted there.
# Run this target on a WSL-native copy instead. The Makefile is not available on
# Windows; invoke the helper directly:
#
#   wsl -d Debian -- bash scripts/dev/wsl-validate.sh

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .
	goimports -w .

vet:
	go vet ./...

# ── Audit (dry run on current machine) ───────────────────────────────────────

audit:
	sudo ./bin/$(BINARY) audit --profile production --format html --output /tmp/hardbox-audit.html

dry-run:
	sudo ./bin/$(BINARY) apply --profile production --dry-run

# ── Release ───────────────────────────────────────────────────────────────────

release:
	goreleaser release --clean

snapshot:
	goreleaser build --snapshot --clean

# ── Cleanup ──────────────────────────────────────────────────────────────────

clean:
	rm -rf bin/ dist/
