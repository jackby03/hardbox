// Copyright (C) 2024 Jack (jackby03)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build linux || darwin || freebsd

package sdk_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/sdk"
)

func buildTestPluginInPkgDir(t *testing.T, srcContent string, outPath string) {
	t.Helper()

	// Go plugins importing internal packages must be located inside the module repo tree during build.
	// We create a temporary package directory under internal/sdk/testdata.
	testDataDir := filepath.Join(".", "testdata")
	if err := os.MkdirAll(testDataDir, 0o755); err != nil {
		t.Fatalf("failed to create testdata dir: %v", err)
	}

	pkgDir, err := os.MkdirTemp(testDataDir, "plugin_*")
	if err != nil {
		t.Fatalf("failed to create temp plugin pkg dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(pkgDir)
	})

	srcFile := filepath.Join(pkgDir, "main.go")
	if err := os.WriteFile(srcFile, []byte(srcContent), 0o600); err != nil {
		t.Fatalf("failed to write test plugin source: %v", err)
	}

	args := []string{"build", "-buildmode=plugin"}
	if isRaceEnabled {
		args = append(args, "-race")
	}
	args = append(args, "-o", outPath, "./"+pkgDir)

	cmd := exec.Command("go", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build test plugin: %v\nOutput: %s", err, string(out))
	}
}

func TestLoadPlugins_NonExistentDir(t *testing.T) {
	nonExistentDir := filepath.Join(t.TempDir(), "does_not_exist")

	entries, err := sdk.LoadPlugins(nonExistentDir)
	if err != nil {
		t.Fatalf("expected no error for non-existent dir, got: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestLoadPlugins_NotADirectory(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "somefile.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := sdk.LoadPlugins(filePath)
	if err == nil {
		t.Fatal("expected error when path is not a directory, got nil")
	}
	if !strings.Contains(err.Error(), "reading plugin dir") {
		t.Errorf("expected 'reading plugin dir' error, got: %v", err)
	}
}

func TestLoadPlugins_IgnoresNonSoAndSubdirectories(t *testing.T) {
	dir := t.TempDir()

	// Create non-.so file and a directory
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("info"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir.so"), 0o755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	entries, err := sdk.LoadPlugins(dir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 loaded entries, got %d", len(entries))
	}
}

func TestLoadPlugins_InvalidSoFile(t *testing.T) {
	dir := t.TempDir()
	invalidSoPath := filepath.Join(dir, "invalid.so")
	if err := os.WriteFile(invalidSoPath, []byte("not a valid elf file"), 0o600); err != nil {
		t.Fatalf("failed to write invalid .so file: %v", err)
	}

	entries, err := sdk.LoadPlugins(dir)
	if err == nil {
		t.Fatal("expected error loading invalid .so file, got nil")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 loaded entries on failure, got %d", len(entries))
	}
	if !strings.Contains(err.Error(), "opening plugin") {
		t.Errorf("expected 'opening plugin' in error, got: %v", err)
	}
}

func TestLoadPlugins_MissingNewSymbol(t *testing.T) {
	pluginDir := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	src := `package main

func NotNew() string {
	return "hello"
}

func main() {}
`
	soPath := filepath.Join(pluginDir, "no_new.so")
	buildTestPluginInPkgDir(t, src, soPath)

	entries, err := sdk.LoadPlugins(pluginDir)
	if err == nil {
		t.Fatal("expected error when 'New' symbol is missing, got nil")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
	if !strings.Contains(err.Error(), "symbol \"New\" not found") {
		t.Errorf("expected missing symbol error, got: %v", err)
	}
}

func TestLoadPlugins_WrongSymbolType(t *testing.T) {
	pluginDir := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	src := `package main

func New() string {
	return "wrong return type"
}

func main() {}
`
	soPath := filepath.Join(pluginDir, "wrong_type.so")
	buildTestPluginInPkgDir(t, src, soPath)

	entries, err := sdk.LoadPlugins(pluginDir)
	if err == nil {
		t.Fatal("expected error when 'New' has wrong type signature, got nil")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
	if !strings.Contains(err.Error(), "symbol \"New\" has wrong type") {
		t.Errorf("expected wrong symbol type error, got: %v", err)
	}
}

func TestLoadPlugins_ValidPlugin(t *testing.T) {
	pluginDir := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	src := `package main

import (
	"context"

	"github.com/hardbox-io/hardbox/internal/modules"
)

type dummyModule struct{}

func (m *dummyModule) Name() string    { return "dummy-plugin" }
func (m *dummyModule) Version() string { return "1.2.3" }

func (m *dummyModule) Audit(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	return []modules.Finding{
		{Check: modules.Check{ID: "DUMMY001"}, Status: modules.StatusCompliant},
	}, nil
}

func (m *dummyModule) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	return nil, nil
}

func New() modules.Module {
	return &dummyModule{}
}

func main() {}
`
	soPath := filepath.Join(pluginDir, "valid.so")
	buildTestPluginInPkgDir(t, src, soPath)

	entries, err := sdk.LoadPlugins(pluginDir)
	if err != nil {
		t.Fatalf("unexpected error loading valid plugin: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 plugin entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Path != soPath {
		t.Errorf("expected Path %q, got %q", soPath, entry.Path)
	}
	if entry.Module == nil {
		t.Fatal("expected Module to be non-nil")
	}
	if entry.Module.Name() != "dummy-plugin" {
		t.Errorf("expected module name 'dummy-plugin', got %q", entry.Module.Name())
	}
	if entry.Module.Version() != "1.2.3" {
		t.Errorf("expected module version '1.2.3', got %q", entry.Module.Version())
	}

	findings, err := entry.Module.Audit(context.Background(), modules.ModuleConfig{})
	if err != nil {
		t.Fatalf("unexpected audit error: %v", err)
	}
	if len(findings) != 1 || findings[0].Check.ID != "DUMMY001" {
		t.Errorf("unexpected audit findings: %+v", findings)
	}
}

func TestLoadPlugins_MultiplePlugins_PartialFailure(t *testing.T) {
	pluginDir := filepath.Join(t.TempDir(), "plugin")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	// 1. Valid plugin (01_valid.so)
	validSrc := `package main

import (
	"context"

	"github.com/hardbox-io/hardbox/internal/modules"
)

type dummyModule struct{}

func (m *dummyModule) Name() string    { return "valid-plugin" }
func (m *dummyModule) Version() string { return "1.0.0" }

func (m *dummyModule) Audit(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	return nil, nil
}

func (m *dummyModule) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	return nil, nil
}

func New() modules.Module { return &dummyModule{} }

func main() {}
`
	buildTestPluginInPkgDir(t, validSrc, filepath.Join(pluginDir, "01_valid.so"))

	// 2. Invalid plugin (02_invalid.so)
	if err := os.WriteFile(filepath.Join(pluginDir, "02_invalid.so"), []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("failed to write invalid plugin: %v", err)
	}

	entries, err := sdk.LoadPlugins(pluginDir)
	if err == nil {
		t.Fatal("expected error due to invalid plugin, got nil")
	}
	if !strings.Contains(err.Error(), "one or more plugins failed to load") {
		t.Errorf("expected combined error message, got: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 successfully loaded plugin entry, got %d", len(entries))
	}
	if entries[0].Module.Name() != "valid-plugin" {
		t.Errorf("expected loaded plugin name 'valid-plugin', got %q", entries[0].Module.Name())
	}
}
