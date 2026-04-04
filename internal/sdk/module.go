// Package sdk exposes the stable public interface for hardbox plugin authors.
// Import this package to implement a custom hardening module that can be loaded
// into hardbox at runtime without forking the core.
//
// # Quickstart
//
// Create a Go file in its own directory with package main:
//
//	package main
//
//	import (
//	    "context"
//	    "github.com/hardbox-io/hardbox/internal/sdk"
//	)
//
//	type myModule struct{}
//
//	func (m *myModule) Name() string    { return "my-module" }
//	func (m *myModule) Version() string { return "1.0.0" }
//
//	func (m *myModule) Audit(ctx context.Context, cfg sdk.ModuleConfig) ([]sdk.Finding, error) {
//	    // inspect the system and return findings
//	    return nil, nil
//	}
//
//	func (m *myModule) Plan(ctx context.Context, cfg sdk.ModuleConfig) ([]sdk.Change, error) {
//	    // return reversible changes needed to reach compliance
//	    return nil, nil
//	}
//
//	// New is the entry-point symbol loaded by hardbox. It must be exported.
//	func New() sdk.Module { return &myModule{} }
//
//	func main() {} // required by go build; ignored at plugin load time
//
// Build and install the plugin:
//
//	go build -buildmode=plugin -o my-module.so .
//	hardbox plugin install my-module.so
package sdk

import "github.com/hardbox-io/hardbox/internal/modules"

// Module is the interface every hardbox hardening module must implement.
// It is identical to internal/modules.Module and guaranteed stable.
type Module = modules.Module

// Re-exported types so plugin authors only need to import this package.
type (
	Finding       = modules.Finding
	Check         = modules.Check
	Change        = modules.Change
	ModuleConfig  = modules.ModuleConfig
	ComplianceRef = modules.ComplianceRef
	Severity      = modules.Severity
	Status        = modules.Status
)

// Severity constants.
const (
	SeverityCritical = modules.SeverityCritical
	SeverityHigh     = modules.SeverityHigh
	SeverityMedium   = modules.SeverityMedium
	SeverityLow      = modules.SeverityLow
	SeverityInfo     = modules.SeverityInfo
)

// Status constants.
const (
	StatusCompliant    = modules.StatusCompliant
	StatusNonCompliant = modules.StatusNonCompliant
	StatusManual       = modules.StatusManual
	StatusSkipped      = modules.StatusSkipped
	StatusError        = modules.StatusError
)

// NewSymbol is the name of the exported constructor that every plugin .so must
// provide: func New() sdk.Module
const NewSymbol = "New"

// PluginEntry holds a loaded plugin module together with the path it was loaded from.
type PluginEntry struct {
	Path   string
	Module modules.Module
}
