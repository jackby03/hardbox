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
// Package provider implements the hardbox Terraform provider.
// The provider exposes a single resource — hardbox_apply — which provisions
// a remote Linux host using the hardbox hardening CLI.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure hardboxProvider implements the provider.Provider interface.
var _ provider.Provider = &hardboxProvider{}
var _ provider.ProviderWithFunctions = &hardboxProvider{}

// hardboxProvider is the top-level provider struct.
type hardboxProvider struct {
	version string
}

// hardboxProviderModel mirrors the provider-level HCL configuration block.
type hardboxProviderModel struct {
	// HardboxVersion pins the hardbox binary version installed on remote hosts.
	// Defaults to "latest" when omitted.
	HardboxVersion types.String `tfsdk:"hardbox_version"`
}

// New returns a factory function for the hardbox provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &hardboxProvider{version: version}
	}
}

func (p *hardboxProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "hardbox"
	resp.Version = p.version
}

func (p *hardboxProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `
The **hardbox** provider provisions Linux system hardening on remote hosts using
the [hardbox](https://github.com/jackby03/hardbox) CLI.

It downloads the hardbox binary, applies a compliance profile, and captures
the audit report — all within a single ` + "`terraform apply`" + ` run.

Supported targets: AWS EC2, GCP Compute Engine, Azure VMs, and any SSH-accessible Linux host.
`,
		Attributes: map[string]schema.Attribute{
			"hardbox_version": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "hardbox release to install on remote hosts (e.g. `v0.3.0`). Defaults to `latest`.",
			},
		},
	}
}

func (p *hardboxProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config hardboxProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	version := "latest"
	if !config.HardboxVersion.IsNull() && !config.HardboxVersion.IsUnknown() {
		version = config.HardboxVersion.ValueString()
	}

	// Pass the resolved version to resources via provider data.
	resp.ResourceData = version
	resp.DataSourceData = version
}

func (p *hardboxProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewHardboxApplyResource,
	}
}

func (p *hardboxProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *hardboxProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{}
}

