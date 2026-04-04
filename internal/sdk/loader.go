//go:build linux || darwin || freebsd

package sdk

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"

	"github.com/hardbox-io/hardbox/internal/modules"
)

// LoadPlugins loads all .so files from dir and returns the modules they export.
// Each .so must export a symbol named "New" of type func() sdk.Module.
//
// If dir does not exist, LoadPlugins returns nil, nil (no plugins is not an error).
// Errors from individual plugins are collected and returned as a single combined
// error after all files have been attempted, so a bad plugin does not block others.
func LoadPlugins(dir string) ([]PluginEntry, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading plugin dir %s: %w", dir, err)
	}

	var loaded []PluginEntry
	var loadErrs []string

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".so" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		m, err := loadPlugin(path)
		if err != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		loaded = append(loaded, PluginEntry{Path: path, Module: m})
	}

	if len(loadErrs) > 0 {
		combined := ""
		for _, e := range loadErrs {
			combined += "\n  " + e
		}
		return loaded, fmt.Errorf("one or more plugins failed to load:%s", combined)
	}
	return loaded, nil
}

func loadPlugin(path string) (modules.Module, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening plugin: %w", err)
	}

	sym, err := p.Lookup(NewSymbol)
	if err != nil {
		return nil, fmt.Errorf("symbol %q not found — plugin must export: func %s() sdk.Module", NewSymbol, NewSymbol)
	}

	newFn, ok := sym.(func() Module)
	if !ok {
		return nil, fmt.Errorf("symbol %q has wrong type — expected func() sdk.Module, got %T", NewSymbol, sym)
	}

	return newFn(), nil
}
