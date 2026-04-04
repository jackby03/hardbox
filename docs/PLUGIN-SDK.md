# hardbox Plugin SDK

The Plugin SDK lets you write custom hardening modules and load them into hardbox at runtime — no forking or recompiling the core required.

## Prerequisites

- Go 1.22+
- Linux, macOS, or FreeBSD (Go's `plugin` package is not supported on Windows)
- CGO enabled (required by `go build -buildmode=plugin`)
- Your plugin must be built with the **same Go version and the same hardbox source tree** as the running binary

## Quickstart

### 1. Create your plugin

Create a directory for your plugin and write a Go file with `package main`:

{% raw %}
```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/hardbox-io/hardbox/internal/sdk"
)

type myModule struct{}

func (m *myModule) Name() string    { return "my-module" }
func (m *myModule) Version() string { return "1.0.0" }

func (m *myModule) Audit(_ context.Context, cfg sdk.ModuleConfig) ([]sdk.Finding, error) {
    check := sdk.Check{
        ID:       "MY-001",
        Title:    "My custom check",
        Severity: sdk.SeverityMedium,
    }

    // inspect the live system...
    ok := true // replace with real check logic

    if !ok {
        return []sdk.Finding{{
            Check:  check,
            Status: sdk.StatusNonCompliant,
            Detail: "condition not met",
        }}, nil
    }
    return []sdk.Finding{{Check: check, Status: sdk.StatusCompliant}}, nil
}

func (m *myModule) Plan(_ context.Context, cfg sdk.ModuleConfig) ([]sdk.Change, error) {
    // return nil, nil if Audit already passed
    return []sdk.Change{{
        Description: "Fix my condition",
        Apply:       func() error { /* apply fix */ return nil },
        Revert:      func() error { /* undo fix */ return nil },
    }}, nil
}

// New is the mandatory entry-point symbol. hardbox calls this to instantiate
// your module. It must be exported and match this exact signature.
func New() sdk.Module { return &myModule{} }

// main is required so the file compiles normally. It is ignored at plugin load time.
func main() {}
```
{% endraw %}

### 2. Build the plugin

```bash
go build -buildmode=plugin -o my-module.so .
```

> **Important:** Build the plugin from within the hardbox source tree (or with the same module at the same version) to ensure type compatibility at load time.

### 3. Install the plugin

```bash
# Copies my-module.so to /etc/hardbox/plugins/ (requires write access)
hardbox plugin install my-module.so
```

Or copy manually:

```bash
sudo cp my-module.so /etc/hardbox/plugins/
```

### 4. Verify the plugin loaded

```bash
hardbox plugin list
```

Output:
```
NAME                     VERSION    PATH
my-module                1.0.0      /etc/hardbox/plugins/my-module.so
```

---

## SDK Reference

All types below are imported from `github.com/hardbox-io/hardbox/internal/sdk`.

### `Module` interface

```go
type Module interface {
    Name() string
    Version() string
    Audit(ctx context.Context, cfg ModuleConfig) ([]Finding, error)
    Plan(ctx context.Context, cfg ModuleConfig) ([]Change, error)
}
```

| Method | Description |
|--------|-------------|
| `Name()` | Unique module identifier, e.g. `"my-module"`. Must not collide with built-in module names. |
| `Version()` | Semver string, e.g. `"1.0.0"`. Used for display only. |
| `Audit()` | Read-only inspection of the live system. Must not modify system state. |
| `Plan()` | Returns reversible changes needed to reach compliance. Changes are not executed here. |

### `Finding`

```go
type Finding struct {
    Check   Check
    Status  Status  // StatusCompliant | StatusNonCompliant | StatusManual | StatusSkipped | StatusError
    Current string  // observed value
    Target  string  // desired value
    Detail  string  // human-readable explanation
}
```

### `Check`

```go
type Check struct {
    ID          string
    Title       string
    Description string
    Remediation string
    Severity    Severity       // SeverityCritical | High | Medium | Low | Info
    Compliance  []ComplianceRef
}
```

### `ComplianceRef`

```go
type ComplianceRef struct {
    Framework string // "CIS", "NIST", "STIG", "PCI-DSS", "HIPAA", "ISO27001"
    Control   string // e.g. "5.2.8", "AC-6", "V-238218"
}
```

### `Change`

```go
type Change struct {
    Description  string
    DryRunOutput string   // shown with --dry-run
    Apply        func() error
    Revert       func() error
}
```

`Apply` and `Revert` must be paired: if `Apply` succeeds, `Revert` must be able to undo it. The engine takes a snapshot before calling `Apply` and calls `Revert` automatically if a later step fails.

### `ModuleConfig`

```go
type ModuleConfig map[string]any
```

Per-module settings from the active profile. To expose configuration for your module, add a section to the YAML profile:

```yaml
modules:
  my-module:
    enabled: true
    my_setting: "value"
```

Then read it in `Audit` / `Plan`:

```go
func (m *myModule) Audit(_ context.Context, cfg sdk.ModuleConfig) ([]sdk.Finding, error) {
    val, _ := cfg["my_setting"].(string)
    // ...
}
```

---

## Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `plugin_dir` | `/etc/hardbox/plugins` | Directory scanned for `.so` files at startup |

Override via config file or environment variable:

```yaml
# /etc/hardbox/config.yaml
plugin_dir: /opt/hardbox/plugins
```

```bash
export HARDBOX_PLUGIN_DIR=/opt/hardbox/plugins
```

Set `plugin_dir: ""` to disable plugin loading entirely.

---

## CLI Reference

### `hardbox plugin list`

Lists all plugins currently loaded from the plugin directory.

```
NAME                     VERSION    PATH
custom-tmp-sticky        1.0.0      /etc/hardbox/plugins/custom-tmp-check.so
```

### `hardbox plugin install <plugin.so>`

Copies a `.so` file into the plugin directory. Creates the directory if it does not exist.

```bash
hardbox plugin install /path/to/my-module.so
# Plugin installed: /etc/hardbox/plugins/my-module.so
```

---

## Platform support

| Platform | Plugin loading |
|----------|---------------|
| Linux    | Supported |
| macOS    | Supported |
| FreeBSD  | Supported |
| Windows  | Not supported (hardbox targets Linux servers) |

---

## Example plugin

A fully working example is available at [`examples/plugin-custom-check/`](../examples/plugin-custom-check/plugin.go). It checks whether `/tmp` has the sticky bit set — a real CIS benchmark requirement.

Build it:

```bash
cd examples/plugin-custom-check
go build -buildmode=plugin -o custom-tmp-check.so .
hardbox plugin install custom-tmp-check.so
hardbox audit
```
