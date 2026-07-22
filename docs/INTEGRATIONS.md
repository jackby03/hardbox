# hardbox — Integrations

hardbox integrates with popular infrastructure-as-code and provisioning tools.
The source code and modules live in the repository, this document maps them.

## Ansible

Ansible role to install and run hardbox on target hosts.

- **Source:** [`ansible-role/hardbox/`](../ansible-role/hardbox/)
- **Galaxy:** `jackby03.hardbox`
- **Supported:** Ubuntu 20.04/22.04/24.04, Debian 11/12, RHEL/Rocky/Alma 8/9

```yaml
- hosts: all
  become: true
  roles:
    - role: jackby03.hardbox
      vars:
        hardbox_profile: cis-level1
```

Install: `ansible-galaxy role install jackby03.hardbox`

## Terraform

Terraform provider for applying hardbox hardening as part of infrastructure-as-code.

- **Source:** [`terraform-provider/`](../terraform-provider/)
- **Registry:** `jackby03/hardbox`

```hcl
provider "hardbox" {
  ssh_user    = "ubuntu"
  ssh_key     = file("~/.ssh/id_ed25519")
}

resource "hardbox_apply" "production" {
  host    = aws_instance.web.public_ip
  profile = "production"
}
```

## cloud-init

cloud-init `user-data` templates that bootstrap hardening on first boot.

- **Templates:** [`cloud-init/`](../cloud-init/)
- **Supported:** AWS, GCP, Azure

```yaml
#cloud-config
write_files:
  - path: /etc/hardbox/config.yaml
    content: |
      profile: cis-level1

runcmd:
  - curl -fsSL https://hardbox.jackby03.com/install.sh | bash
  - hardbox apply --profile cis-level1
```

## Plugin SDK

Build custom hardening modules without forking the project.

- **Guide:** [`PLUGIN-SDK.md`](PLUGIN-SDK.md)
- **Example:** [`examples/plugin-custom-check/`](../examples/plugin-custom-check/)
