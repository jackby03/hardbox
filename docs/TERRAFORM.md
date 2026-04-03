# hardbox — Terraform Provider

The `jackby03/hardbox` Terraform provider applies OS hardening to remote Linux
hosts as part of your infrastructure-as-code workflow. It installs the hardbox
binary, runs a compliance profile, and surfaces audit findings in Terraform state.

Supported targets: **AWS EC2**, **GCP Compute Engine**, **Azure VMs**, and any
SSH-accessible Linux host.

---

## Installation

Add the provider to your `required_providers` block:

```hcl
terraform {
  required_providers {
    hardbox = {
      source  = "jackby03/hardbox"
      version = "~> 0.3"
    }
  }
}
```

```bash
terraform init
```

---

## Provider Configuration

```hcl
provider "hardbox" {
  # Optional: pin the hardbox binary version installed on all managed hosts.
  # Defaults to "latest" if omitted.
  hardbox_version = "v0.3.0"
}
```

| Argument | Type | Default | Description |
|---|---|---|---|
| `hardbox_version` | string | `"latest"` | hardbox release tag to install on remote hosts |

---

## Resource: `hardbox_apply`

Provisions a remote Linux host with hardbox OS hardening.

### What it does

1. Connects to the host over SSH.
2. Downloads the hardbox binary and verifies its SHA-256 checksum.
3. Runs `hardbox apply` with the selected compliance profile.
4. Captures the audit report and surfaces finding counts in state.
5. On `terraform destroy`, runs `hardbox rollback apply --last`.

### Arguments

#### SSH connection

| Argument | Required | Description |
|---|---|---|
| `host` | yes | IP address or hostname of the target |
| `port` | no | SSH port (default: `22`) |
| `user` | no | SSH username (default: `root`) |
| `private_key` | no | PEM-encoded SSH private key |
| `agent_socket` | no | Path to SSH agent socket (`$SSH_AUTH_SOCK`) |

#### hardbox options

| Argument | Default | Description |
|---|---|---|
| `profile` | required | Compliance profile name |
| `hardbox_version` | provider default | Override version for this resource |
| `dry_run` | `false` | Preview changes without applying |
| `rollback_on_failure` | `true` | Rollback automatically on failure |
| `report_format` | `"json"` | `json`, `html`, `text`, `markdown` |
| `fail_on_critical` | `true` | Fail apply on critical findings |
| `fail_on_high` | `true` | Fail apply on high findings |

### Computed attributes

| Attribute | Description |
|---|---|
| `id` | `<host>:<profile>@<applied_at>` |
| `applied_at` | RFC3339 timestamp of last apply |
| `installed_version` | hardbox version installed on the host |
| `report_content` | Full audit report (JSON/HTML/text) |
| `findings` | Map of severity counts: `{critical, high, medium, low, info}` |

---

## Examples

### AWS EC2

```hcl
resource "hardbox_apply" "web" {
  host        = aws_instance.web.public_ip
  user        = "ubuntu"
  private_key = file("~/.ssh/id_rsa")

  profile             = "cloud-aws"
  report_format       = "json"
  fail_on_critical    = true
  fail_on_high        = true
  rollback_on_failure = true
}

output "findings" {
  value = hardbox_apply.web.findings
}
```

Full example: [`examples/aws/`](../terraform-provider/examples/aws/)

### GCP Compute Engine

```hcl
resource "hardbox_apply" "web" {
  host        = google_compute_instance.web.network_interface[0].network_ip
  user        = "ubuntu"
  private_key = file("~/.ssh/id_rsa")

  profile       = "cloud-gcp"
  report_format = "json"
}
```

Full example: [`examples/gcp/`](../terraform-provider/examples/gcp/)

### Azure VM

```hcl
resource "hardbox_apply" "vm" {
  host        = azurerm_network_interface.nic.private_ip_address
  user        = "azureuser"
  private_key = file("~/.ssh/id_rsa")

  profile       = "cloud-azure"
  report_format = "json"
}
```

Full example: [`examples/azure/`](../terraform-provider/examples/azure/)

### Audit-only (no changes)

```hcl
resource "hardbox_apply" "audit" {
  host        = var.host_ip
  user        = "ubuntu"
  private_key = file(var.key_path)

  profile  = "cis-level2"
  dry_run  = true   # --dry-run: no changes applied
}
```

---

## Profiles

| Profile | Framework |
|---|---|
| `cis-level1` | CIS Benchmarks Level 1 |
| `cis-level2` | CIS Benchmarks Level 2 |
| `pci-dss` | PCI-DSS v4.0 |
| `stig` | DISA STIG |
| `hipaa` | HIPAA Security Rule |
| `iso27001` | ISO/IEC 27001:2022 |
| `cloud-aws` | CIS AWS Foundations v2.0 |
| `cloud-gcp` | CIS GCP Foundations v2.0 |
| `cloud-azure` | CIS Azure Foundations v2.1 |
| `production` | hardbox curated |
| `development` | hardbox curated |

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Terraform apply (with hardbox hardening)
  run: terraform apply -auto-approve
  env:
    TF_VAR_private_key: ${{ secrets.SSH_PRIVATE_KEY }}
```

### GitLab CI

```yaml
terraform:
  script:
    - terraform init
    - terraform apply -auto-approve
  variables:
    TF_VAR_private_key: $SSH_PRIVATE_KEY
```

---

## Building from source

```bash
cd terraform-provider/
go build -o terraform-provider-hardbox .

# Install locally for testing
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/jackby03/hardbox/0.3.0/linux_amd64
cp terraform-provider-hardbox \
  ~/.terraform.d/plugins/registry.terraform.io/jackby03/hardbox/0.3.0/linux_amd64/
```

---

## Publishing to Terraform Registry

The provider is published to the [Terraform Registry](https://registry.terraform.io/providers/jackby03/hardbox)
via GitHub Actions on release tag push. The registry indexes `terraform-provider/`
as the provider source directory.
