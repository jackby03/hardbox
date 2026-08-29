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

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestNew(t *testing.T) {
	t.Parallel()

	factory := New("1.0.0")
	if factory == nil {
		t.Fatal("expected non-nil factory function")
	}

	p := factory()
	if p == nil {
		t.Fatal("expected non-nil provider")
	}

	hp, ok := p.(*hardboxProvider)
	if !ok {
		t.Fatalf("expected *hardboxProvider, got %T", p)
	}

	if hp.version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got '%s'", hp.version)
	}
}

func TestHardboxProvider_Metadata(t *testing.T) {
	t.Parallel()

	p := &hardboxProvider{version: "0.5.0"}
	req := provider.MetadataRequest{}
	resp := provider.MetadataResponse{}

	p.Metadata(context.Background(), req, &resp)

	if resp.TypeName != "hardbox" {
		t.Errorf("expected TypeName 'hardbox', got '%s'", resp.TypeName)
	}
	if resp.Version != "0.5.0" {
		t.Errorf("expected Version '0.5.0', got '%s'", resp.Version)
	}
}

func TestHardboxProvider_Schema(t *testing.T) {
	t.Parallel()

	p := &hardboxProvider{version: "0.5.0"}
	req := provider.SchemaRequest{}
	resp := provider.SchemaResponse{}

	p.Schema(context.Background(), req, &resp)

	if resp.Schema.Attributes == nil {
		t.Fatal("expected non-nil Schema.Attributes")
	}

	attr, exists := resp.Schema.Attributes["hardbox_version"]
	if !exists {
		t.Error("expected 'hardbox_version' attribute in Schema")
	}
	if attr == nil {
		t.Error("expected non-nil 'hardbox_version' attribute")
	}
}

func TestHardboxProvider_Resources_DataSources_Functions(t *testing.T) {
	t.Parallel()

	p := &hardboxProvider{version: "1.0.0"}
	ctx := context.Background()

	resources := p.Resources(ctx)
	if len(resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(resources))
	} else {
		res := resources[0]()
		if res == nil {
			t.Error("expected non-nil resource from factory")
		}
	}

	dataSources := p.DataSources(ctx)
	if len(dataSources) != 0 {
		t.Errorf("expected 0 data sources, got %d", len(dataSources))
	}

	functions := p.Functions(ctx)
	if len(functions) != 0 {
		t.Errorf("expected 0 functions, got %d", len(functions))
	}
}

func TestHardboxProvider_Configure(t *testing.T) {
	t.Parallel()

	schemaType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"hardbox_version": tftypes.String,
		},
	}

	invalidSchemaType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"hardbox_version": tftypes.Number,
		},
	}

	tests := []struct {
		name                 string
		configVal            tftypes.Value
		expectedResourceData string
		expectError          bool
	}{
		{
			name: "default version when hardbox_version is null",
			configVal: tftypes.NewValue(schemaType, map[string]tftypes.Value{
				"hardbox_version": tftypes.NewValue(tftypes.String, nil),
			}),
			expectedResourceData: "latest",
			expectError:          false,
		},
		{
			name: "custom version set",
			configVal: tftypes.NewValue(schemaType, map[string]tftypes.Value{
				"hardbox_version": tftypes.NewValue(tftypes.String, "v0.4.2"),
			}),
			expectedResourceData: "v0.4.2",
			expectError:          false,
		},
		{
			name: "schema error",
			configVal: tftypes.NewValue(invalidSchemaType, map[string]tftypes.Value{
				"hardbox_version": tftypes.NewValue(tftypes.Number, 123),
			}),
			expectedResourceData: "",
			expectError:          true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := &hardboxProvider{version: "1.0.0"}
			ctx := context.Background()

			req := provider.ConfigureRequest{
				Config: tfsdk.Config{
					Raw:    tt.configVal,
					Schema: p.schema(ctx),
				},
			}
			resp := provider.ConfigureResponse{}

			p.Configure(ctx, req, &resp)

			if tt.expectError {
				if !resp.Diagnostics.HasError() {
					t.Errorf("expected diagnostic error, got none")
				}
				return
			}

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostic error: %v", resp.Diagnostics)
			}

			if resp.ResourceData != tt.expectedResourceData {
				t.Errorf("expected ResourceData '%s', got '%v'", tt.expectedResourceData, resp.ResourceData)
			}
			if resp.DataSourceData != tt.expectedResourceData {
				t.Errorf("expected DataSourceData '%s', got '%v'", tt.expectedResourceData, resp.DataSourceData)
			}
		})
	}
}

// helper to get schema for tests
func (p *hardboxProvider) schema(ctx context.Context) schema.Schema {
	var resp provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &resp)
	return resp.Schema
}

// Ensure unused import warning isn't triggered for types
var _ = types.String{}
