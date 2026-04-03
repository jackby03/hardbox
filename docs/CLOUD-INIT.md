# hardbox — cloud-init Integration

hardbox ships ready-to-use cloud-init `user-data` templates that bootstrap
OS hardening on first boot and configure a systemd timer for periodic
re-hardening. Reports are automatically uploaded to cloud-native object storage.

---

## Templates

| Template | Cloud | Profile | Report Destination |
|---|---|---|---|
| `cloud-init/aws-user-data.yaml` | Amazon EC2 | `cloud-aws` | Amazon S3 |
| `cloud-init/gcp-user-data.yaml` | GCP Compute Engine | `cloud-gcp` | Google Cloud Storage |
| `cloud-init/azure-user-data.yaml` | Azure VMs | `cloud-azure` | Azure Blob Storage |

All templates share the same structure:

1. **Install** — downloads the hardbox binary and verifies its SHA-256 checksum.
2. **Apply** — runs `hardbox apply` with the selected profile on first boot.
3. **Report** — uploads the HTML audit report to cloud-native object storage.
4. **Timer** — schedules daily re-hardening via a systemd timer.

---

## Quick Start

### Amazon EC2

```bash
# 1. Edit the template variables
cp cloud-init/aws-user-data.yaml my-aws-user-data.yaml
# Set HARDBOX_VERSION, HARDBOX_PROFILE, HARDBOX_REPORT_S3

# 2. Launch instance with user-data
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.micro \
  --iam-instance-profile Name=my-instance-profile \
  --user-data file://my-aws-user-data.yaml \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=hardbox-demo}]'

# 3. Monitor cloud-init progress
aws ec2 get-console-output --instance-id i-xxxx --latest
```

**IAM permissions required** on the instance role:
```json
{
  "Effect": "Allow",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::YOUR-BUCKET/hardbox/*"
}
```

### GCP Compute Engine

```bash
# 1. Edit the template variables
cp cloud-init/gcp-user-data.yaml my-gcp-user-data.yaml
# Set HARDBOX_VERSION, HARDBOX_PROFILE, HARDBOX_REPORT_GCS

# 2. Create instance with user-data (metadata key must be 'user-data')
gcloud compute instances create hardbox-demo \
  --machine-type e2-medium \
  --image-family ubuntu-2204-lts \
  --image-project ubuntu-os-cloud \
  --service-account my-sa@my-project.iam.gserviceaccount.com \
  --scopes cloud-platform \
  --metadata-from-file user-data=my-gcp-user-data.yaml

# 3. Monitor cloud-init logs
gcloud compute ssh hardbox-demo -- "journalctl -u cloud-init -f"
```

**IAM permissions required** on the service account:
```
roles/storage.objectCreator  (on the GCS bucket)
```

### Azure Virtual Machines

```bash
# 1. Edit the template variables
cp cloud-init/azure-user-data.yaml my-azure-user-data.yaml
# Set HARDBOX_VERSION, HARDBOX_PROFILE, HARDBOX_REPORT_CONTAINER

# 2. Create VM with custom-data (az CLI base64-encodes automatically)
az vm create \
  --resource-group my-rg \
  --name hardbox-demo \
  --image Ubuntu2204 \
  --size Standard_B2s \
  --assign-identity \
  --custom-data my-azure-user-data.yaml \
  --admin-username azureuser \
  --ssh-key-values ~/.ssh/id_rsa.pub

# 3. Grant Storage Blob Data Contributor to the VM's managed identity
PRINCIPAL_ID=$(az vm show -g my-rg -n hardbox-demo \
  --query identity.principalId -o tsv)
az role assignment create \
  --assignee "$PRINCIPAL_ID" \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/SUB_ID/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/myaccount/blobServices/default/containers/hardbox"

# 4. Monitor cloud-init logs
az vm run-command invoke -g my-rg -n hardbox-demo \
  --command-id RunShellScript \
  --scripts "journalctl -u cloud-init --no-pager | tail -50"
```

---

## Configuration Reference

Each template writes `/etc/hardbox/cloud-init.env` with the following variables:

| Variable | Default | Description |
|---|---|---|
| `HARDBOX_VERSION` | `latest` | Release tag (e.g. `v0.3.0`) or `latest` |
| `HARDBOX_PROFILE` | provider-specific | Compliance profile to apply |
| `HARDBOX_REPORT_S3` / `_GCS` / `_CONTAINER` | `CHANGE-ME` | Object storage destination |
| `HARDBOX_SCHEDULE` | `daily` | Re-hardening frequency (systemd OnCalendar syntax) |
| `HARDBOX_INSTALL_DIR` | `/usr/local/bin` | Binary installation path |
| `HARDBOX_REPORT_DIR` | `/var/lib/hardbox/reports` | Local report directory |

To change the profile or schedule after first boot:

```bash
# Edit the env file
sudo vi /etc/hardbox/cloud-init.env

# Run hardening manually
sudo systemctl start hardbox-harden.service

# Check status
sudo systemctl status hardbox-harden.service
sudo journalctl -u hardbox -n 50
```

---

## Systemd Timer

The templates install a systemd timer that re-hardens the system daily.
This ensures configuration drift is detected and corrected automatically.

```bash
# View timer status
systemctl status hardbox-harden.timer
systemctl list-timers hardbox-harden.timer

# Change schedule (e.g. every 6 hours)
sudo sed -i 's/OnCalendar=daily/OnCalendar=*-*-* 00,06,12,18:00:00/' \
  /etc/systemd/system/hardbox-harden.timer
sudo systemctl daemon-reload
sudo systemctl restart hardbox-harden.timer
```

---

## Binary Verification

All templates verify the SHA-256 checksum of the downloaded binary before
installation. If the checksum does not match, installation fails and the
system is not hardened — the failure is logged to syslog/journal.

Checksums are published in the GitHub release assets alongside each binary:
`hardbox_<version>_checksums.txt`

---

## Customising the Profile

To use a different profile (e.g. `cis-level2` for maximum hardening):

```yaml
# In cloud-init.env content block:
HARDBOX_PROFILE=cis-level2
```

Available profiles: `cis-level1`, `cis-level2`, `pci-dss`, `stig`, `hipaa`,
`iso27001`, `cloud-aws`, `cloud-gcp`, `cloud-azure`, `production`, `development`

See [COMPLIANCE.md](COMPLIANCE.md) for a full coverage matrix.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Checksum mismatch` | Corrupt or tampered download | Check network/proxy; re-run install |
| `hardbox: command not found` | Install failed silently | Check `/var/log/cloud-init-output.log` |
| `Report upload failed` | Missing IAM/RBAC permissions | Grant object write permission to instance identity |
| Timer not running | systemd not reloaded | `systemctl daemon-reload && systemctl enable --now hardbox-harden.timer` |

Cloud-init logs:
```bash
# All cloud providers
cat /var/log/cloud-init-output.log
journalctl -u cloud-init --no-pager

# hardbox-specific logs
journalctl -t hardbox --no-pager
```
