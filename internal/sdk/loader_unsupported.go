//go:build !linux && !darwin && !freebsd

package sdk

import "fmt"

// LoadPlugins is not supported on this platform. Go's plugin package requires
// Linux, macOS, or FreeBSD. This stub returns an informational error so the
// engine can log a warning and continue without plugins.
func LoadPlugins(_ string) ([]PluginEntry, error) {
	return nil, fmt.Errorf("plugin loading is not supported on this platform (requires Linux, macOS, or FreeBSD)")
}
