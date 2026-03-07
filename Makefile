.PHONY: build run test lint clean install

BINARY := hardbox
CMD     := ./cmd/hardbox
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-X main.version=$(VERSION)"

# ── Build ────────────────────────────────────────────────────────────────────

build:
	go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

run: build
	sudo ./bin/$(BINARY)

install: build
	sudo install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

# ── Development ──────────────────────────────────────────────────────────────

test:
	go test ./... -v -race

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
