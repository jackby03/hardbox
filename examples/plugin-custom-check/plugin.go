// Package main is an example hardbox plugin that checks whether the /tmp
// directory has the sticky bit set (permissions 1777). This is a real
// hardening requirement: without the sticky bit, any user can delete files
// owned by others inside /tmp.
//
// # Build
//
//	go build -buildmode=plugin -o custom-tmp-check.so .
//
// # Install
//
//	hardbox plugin install custom-tmp-check.so
//
// # Verify
//
//	hardbox plugin list
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hardbox-io/hardbox/internal/sdk"
)

// tmpStickyModule checks that /tmp has the sticky bit set.
type tmpStickyModule struct{}

func (m *tmpStickyModule) Name() string    { return "custom-tmp-sticky" }
func (m *tmpStickyModule) Version() string { return "1.0.0" }

func (m *tmpStickyModule) Audit(_ context.Context, _ sdk.ModuleConfig) ([]sdk.Finding, error) {
	check := sdk.Check{
		ID:          "CUSTOM-001",
		Title:       "/tmp sticky bit",
		Description: "The /tmp directory must have the sticky bit set (mode 1777) so that users cannot delete each other's files.",
		Remediation: "Run: chmod +t /tmp",
		Severity:    sdk.SeverityMedium,
		Compliance: []sdk.ComplianceRef{
			{Framework: "CIS", Control: "1.1.2"},
		},
	}

	info, err := os.Stat("/tmp")
	if err != nil {
		return []sdk.Finding{{
			Check:  check,
			Status: sdk.StatusError,
			Detail: fmt.Sprintf("could not stat /tmp: %v", err),
		}}, nil
	}

	mode := info.Mode()
	if mode&os.ModeSticky == 0 {
		return []sdk.Finding{{
			Check:   check,
			Status:  sdk.StatusNonCompliant,
			Current: fmt.Sprintf("%04o", mode.Perm()),
			Target:  "1777",
			Detail:  "/tmp does not have the sticky bit set",
		}}, nil
	}

	return []sdk.Finding{{
		Check:   check,
		Status:  sdk.StatusCompliant,
		Current: fmt.Sprintf("%04o", mode.Perm()|os.ModeSticky),
		Target:  "1777",
	}}, nil
}

func (m *tmpStickyModule) Plan(_ context.Context, _ sdk.ModuleConfig) ([]sdk.Change, error) {
	info, err := os.Stat("/tmp")
	if err != nil {
		return nil, fmt.Errorf("stat /tmp: %w", err)
	}

	if info.Mode()&os.ModeSticky != 0 {
		return nil, nil // already compliant
	}

	return []sdk.Change{{
		Description:  "Set sticky bit on /tmp (chmod +t /tmp)",
		DryRunOutput: "chmod 1777 /tmp",
		Apply: func() error {
			return os.Chmod("/tmp", 0o1777)
		},
		Revert: func() error {
			return os.Chmod("/tmp", info.Mode().Perm())
		},
	}}, nil
}

// New is the entry-point symbol loaded by hardbox.
// It must be exported and have the signature: func New() sdk.Module
func New() sdk.Module {
	return &tmpStickyModule{}
}

// main is required so the file compiles with `go build` in addition to
// `go build -buildmode=plugin`. It is not called when loaded as a plugin.
func main() {}
