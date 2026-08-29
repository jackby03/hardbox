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

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestNewHardboxApplyResource(t *testing.T) {
	t.Parallel()

	r := NewHardboxApplyResource()
	if r == nil {
		t.Fatal("expected non-nil resource from NewHardboxApplyResource")
	}
}

func TestHardboxApplyResource_Metadata(t *testing.T) {
	t.Parallel()

	r := &hardboxApplyResource{}
	req := resource.MetadataRequest{
		ProviderTypeName: "hardbox",
	}
	var resp resource.MetadataResponse

	r.Metadata(context.Background(), req, &resp)

	expectedTypeName := "hardbox_apply"
	if resp.TypeName != expectedTypeName {
		t.Errorf("expected TypeName %q, got %q", expectedTypeName, resp.TypeName)
	}
}

func TestHardboxApplyResource_Schema(t *testing.T) {
	t.Parallel()

	r := &hardboxApplyResource{}
	req := resource.SchemaRequest{}
	var resp resource.SchemaResponse

	r.Schema(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics error in Schema: %v", resp.Diagnostics)
	}

	expectedAttrs := []string{
		"id", "host", "port", "user", "private_key", "agent_socket", "host_key",
		"profile", "hardbox_version", "dry_run", "rollback_on_failure",
		"report_format", "fail_on_critical", "fail_on_high",
		"report_content", "applied_at", "installed_version", "findings",
	}

	for _, attr := range expectedAttrs {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("expected attribute %q missing in schema", attr)
		}
	}
}

func TestHardboxApplyResource_Configure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		providerData    any
		expectedVersion string
		expectError     bool
	}{
		{
			name:            "nil provider data",
			providerData:    nil,
			expectedVersion: "",
			expectError:     false,
		},
		{
			name:            "valid string provider data",
			providerData:    "v1.2.3",
			expectedVersion: "v1.2.3",
			expectError:     false,
		},
		{
			name:            "invalid non-string provider data",
			providerData:    12345,
			expectedVersion: "",
			expectError:     true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &hardboxApplyResource{}
			req := resource.ConfigureRequest{
				ProviderData: tc.providerData,
			}
			var resp resource.ConfigureResponse

			r.Configure(context.Background(), req, &resp)

			if tc.expectError {
				if !resp.Diagnostics.HasError() {
					t.Errorf("expected error in Configure, got none")
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Errorf("unexpected error in Configure: %v", resp.Diagnostics)
				}
				if r.hardboxVersion != tc.expectedVersion {
					t.Errorf("expected hardboxVersion %q, got %q", tc.expectedVersion, r.hardboxVersion)
				}
			}
		})
	}
}

func TestHardboxApplyResource_ImportState(t *testing.T) {
	t.Parallel()

	r := &hardboxApplyResource{}
	req := resource.ImportStateRequest{}
	var resp resource.ImportStateResponse

	r.ImportState(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Errorf("expected error in ImportState, got none")
	}

	expectedSummary := "Import not supported"
	found := false
	for _, diag := range resp.Diagnostics {
		if diag.Summary() == expectedSummary {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected diagnostic summary %q not found", expectedSummary)
	}
}
