package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/jackby03/terraform-provider-hardbox/internal/hardbox"
)

// Ensure hardboxApplyResource implements resource.Resource.
var _ resource.Resource = &hardboxApplyResource{}
var _ resource.ResourceWithImportState = &hardboxApplyResource{}

// hardboxApplyResource provisions a remote host with hardbox.
type hardboxApplyResource struct {
	hardboxVersion string
}

// hardboxApplyModel is the Terraform state schema for hardbox_apply.
type hardboxApplyModel struct {
	// --- Identity ---
	ID types.String `tfsdk:"id"`

	// --- SSH connection ---
	Host        types.String `tfsdk:"host"`
	Port        types.Int64  `tfsdk:"port"`
	User        types.String `tfsdk:"user"`
	PrivateKey  types.String `tfsdk:"private_key"`
	AgentSocket types.String `tfsdk:"agent_socket"`
	HostKey     types.String `tfsdk:"host_key"`

	// --- hardbox configuration ---
	Profile            types.String `tfsdk:"profile"`
	HardboxVersion     types.String `tfsdk:"hardbox_version"`
	DryRun             types.Bool   `tfsdk:"dry_run"`
	RollbackOnFailure  types.Bool   `tfsdk:"rollback_on_failure"`
	ReportFormat       types.String `tfsdk:"report_format"`
	FailOnCritical     types.Bool   `tfsdk:"fail_on_critical"`
	FailOnHigh         types.Bool   `tfsdk:"fail_on_high"`

	// --- Computed outputs ---
	ReportContent  types.String `tfsdk:"report_content"`
	AppliedAt      types.String `tfsdk:"applied_at"`
	HardboxVersion_ types.String `tfsdk:"installed_version"`
	Findings       types.Map    `tfsdk:"findings"`
}

func NewHardboxApplyResource() resource.Resource {
	return &hardboxApplyResource{}
}

func (r *hardboxApplyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_apply"
}

func (r *hardboxApplyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `
Provisions a remote Linux host with hardbox OS hardening.

The resource:
1. Connects to the host over SSH.
2. Downloads the hardbox binary and verifies its SHA-256 checksum.
3. Runs ` + "`hardbox apply`" + ` with the selected compliance profile.
4. Captures the audit report and surfaces findings counts in Terraform state.
5. On destroy, runs ` + "`hardbox rollback apply --last`" + ` to restore the pre-hardening snapshot.

## Example

` + "```hcl" + `
resource "hardbox_apply" "web" {
  host        = aws_instance.web.public_ip
  user        = "ubuntu"
  private_key = file("~/.ssh/id_rsa")
  profile     = "cloud-aws"
}
` + "```",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier: `<host>:<profile>@<applied_at>`.",
			},

			// SSH connection
			"host": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "IP address or hostname of the target Linux host.",
			},
			"port": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "SSH port (default: 22).",
			},
			"user": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("root"),
				MarkdownDescription: "SSH username (default: `root`).",
			},
			"private_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "PEM-encoded SSH private key. Mutually exclusive with `agent_socket`.",
			},
			"agent_socket": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Path to SSH agent socket (e.g. `$SSH_AUTH_SOCK`). Mutually exclusive with `private_key`.",
			},
			"host_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: false,
				MarkdownDescription: `Base64-encoded SSH public host key of the target server.
Used to verify the server identity and prevent MITM attacks.
Obtain with: ` + "`ssh-keyscan -t ed25519 <host> | awk '{print $3}'`" + `
When omitted, the system ` + "`~/.ssh/known_hosts`" + ` file is used for verification.`,
			},

			// hardbox options
			"profile": schema.StringAttribute{
				Required: true,
				MarkdownDescription: `Compliance profile to apply. Any built-in profile is valid:
` + "`cis-level1`" + `, ` + "`cis-level2`" + `, ` + "`pci-dss`" + `, ` + "`stig`" + `, ` + "`hipaa`" + `,
` + "`iso27001`" + `, ` + "`cloud-aws`" + `, ` + "`cloud-gcp`" + `, ` + "`cloud-azure`" + `,
` + "`production`" + `, ` + "`development`" + `.`,
			},
			"hardbox_version": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Override the provider-level `hardbox_version` for this resource.",
			},
			"dry_run": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Pass `--dry-run` to hardbox — preview changes without applying (default: `false`).",
			},
			"rollback_on_failure": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Run `hardbox rollback apply --last` when hardbox apply fails (default: `true`).",
			},
			"report_format": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("json"),
				MarkdownDescription: "Audit report format: `json`, `html`, `text`, `markdown` (default: `json`).",
			},
			"fail_on_critical": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Fail the Terraform apply if critical findings are detected (default: `true`).",
			},
			"fail_on_high": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Fail the Terraform apply if high findings are detected (default: `true`).",
			},

			// Computed outputs
			"report_content": schema.StringAttribute{
				Computed:            true,
				Sensitive:           false,
				MarkdownDescription: "Contents of the hardbox audit report (JSON/HTML/text).",
			},
			"applied_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "RFC3339 timestamp of when hardbox was last applied.",
			},
			"installed_version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The hardbox version string installed on the target host.",
			},
			"findings": schema.MapAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Map of finding severity counts: `{critical, high, medium, low, info}`.",
			},
		},
	}
}

func (r *hardboxApplyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	version, ok := req.ProviderData.(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected string (hardbox version), got %T", req.ProviderData),
		)
		return
	}
	r.hardboxVersion = version
}

func (r *hardboxApplyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hardboxApplyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.applyHardening(ctx, &plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *hardboxApplyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// hardbox_apply is a provisioner-style resource; state reflects last apply.
	// Read is a no-op — the resource is fully managed by Create/Update/Delete.
	var state hardboxApplyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *hardboxApplyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan hardboxApplyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.applyHardening(ctx, &plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *hardboxApplyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state hardboxApplyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Running hardbox rollback on destroy", map[string]any{
		"host":    state.Host.ValueString(),
		"profile": state.Profile.ValueString(),
	})

	conn, err := hardbox.NewSSHClient(hardbox.SSHConfig{
		Host:        state.Host.ValueString(),
		Port:        int(state.Port.ValueInt64()),
		User:        state.User.ValueString(),
		PrivateKey:  state.PrivateKey.ValueString(),
		AgentSocket: state.AgentSocket.ValueString(),
		HostKey:     state.HostKey.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Rollback skipped — SSH connection failed",
			fmt.Sprintf("Could not connect to %s: %s", state.Host.ValueString(), err),
		)
		return
	}
	defer conn.Close()

	out, err := conn.Run("hardbox rollback apply --last --non-interactive")
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Rollback command failed",
			fmt.Sprintf("hardbox rollback apply --last failed: %s\nOutput: %s", err, out),
		)
	} else {
		tflog.Info(ctx, "Rollback completed", map[string]any{"output": out})
	}
}

func (r *hardboxApplyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.AddError(
		"Import not supported",
		"hardbox_apply is a provisioner resource and cannot be imported. Remove it from state with `terraform state rm` and re-apply.",
	)
}

// applyHardening executes the full install + apply flow on the remote host.
func (r *hardboxApplyResource) applyHardening(
	ctx context.Context,
	m *hardboxApplyModel,
	addError func(summary, detail string),
) {
	version := r.hardboxVersion
	if !m.HardboxVersion.IsNull() && !m.HardboxVersion.IsUnknown() && m.HardboxVersion.ValueString() != "" {
		version = m.HardboxVersion.ValueString()
	}

	tflog.Info(ctx, "Connecting to target host", map[string]any{
		"host":    m.Host.ValueString(),
		"profile": m.Profile.ValueString(),
		"version": version,
	})

	conn, err := hardbox.NewSSHClient(hardbox.SSHConfig{
		Host:        m.Host.ValueString(),
		Port:        int(m.Port.ValueInt64()),
		User:        m.User.ValueString(),
		PrivateKey:  m.PrivateKey.ValueString(),
		AgentSocket: m.AgentSocket.ValueString(),
		HostKey:     m.HostKey.ValueString(),
	})
	if err != nil {
		addError("SSH connection failed", fmt.Sprintf("Cannot connect to %s: %s", m.Host.ValueString(), err))
		return
	}
	defer conn.Close()

	// Step 1: Install hardbox with checksum verification.
	installedVersion, err := hardbox.Install(ctx, conn, version)
	if err != nil {
		addError("hardbox installation failed", err.Error())
		return
	}
	tflog.Info(ctx, "hardbox installed", map[string]any{"version": installedVersion})

	// Step 2: Apply hardening profile.
	reportPath := fmt.Sprintf("/var/lib/hardbox/reports/tf-%d.%s",
		time.Now().Unix(), m.ReportFormat.ValueString())

	applyCmd := strings.Join([]string{
		"hardbox apply",
		"--profile", m.Profile.ValueString(),
		"--format", m.ReportFormat.ValueString(),
		"--output", reportPath,
		"--non-interactive",
	}, " ")
	if m.DryRun.ValueBool() {
		applyCmd += " --dry-run"
	}

	applyOut, applyErr := conn.Run(applyCmd)
	tflog.Debug(ctx, "hardbox apply output", map[string]any{"output": applyOut})

	if applyErr != nil {
		if m.RollbackOnFailure.ValueBool() {
			tflog.Warn(ctx, "Apply failed — running rollback", map[string]any{"error": applyErr.Error()})
			rbOut, rbErr := conn.Run("hardbox rollback apply --last --non-interactive")
			if rbErr != nil {
				addError("hardbox apply + rollback failed",
					fmt.Sprintf("Apply error: %s\nRollback error: %s\nRollback output: %s", applyErr, rbErr, rbOut))
				return
			}
			tflog.Info(ctx, "Rollback completed", map[string]any{"output": rbOut})
		}
		addError("hardbox apply failed", fmt.Sprintf("%s\nOutput: %s", applyErr, applyOut))
		return
	}

	// Step 3: Fetch report content.
	reportContent, err := conn.ReadFile(reportPath)
	if err != nil {
		tflog.Warn(ctx, "Could not read report file", map[string]any{"path": reportPath, "error": err.Error()})
		reportContent = ""
	}

	// Step 4: Parse findings from JSON report (best-effort).
	findings := hardbox.ParseFindings(reportContent, m.ReportFormat.ValueString())

	// Step 5: Check thresholds.
	if m.FailOnCritical.ValueBool() && findings["critical"] != "0" && findings["critical"] != "" {
		addError("hardbox: critical findings detected",
			fmt.Sprintf("Profile %s reported %s critical findings. Review the report.", m.Profile.ValueString(), findings["critical"]))
		return
	}
	if m.FailOnHigh.ValueBool() && findings["high"] != "0" && findings["high"] != "" {
		addError("hardbox: high findings detected",
			fmt.Sprintf("Profile %s reported %s high findings. Review the report.", m.Profile.ValueString(), findings["high"]))
		return
	}

	// Step 6: Populate state.
	now := time.Now().UTC().Format(time.RFC3339)
	m.ID = types.StringValue(fmt.Sprintf("%s:%s@%s", m.Host.ValueString(), m.Profile.ValueString(), now))
	m.AppliedAt = types.StringValue(now)
	m.HardboxVersion_ = types.StringValue(installedVersion)
	m.ReportContent = types.StringValue(reportContent)
	m.HardboxVersion = types.StringValue(version)

	findingsMap := make(map[string]attr.Value, len(findings))
	for k, v := range findings {
		findingsMap[k] = types.StringValue(v)
	}
	m.Findings, _ = types.MapValue(types.StringType, findingsMap)
}
