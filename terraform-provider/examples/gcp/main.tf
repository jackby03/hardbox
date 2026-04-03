terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    hardbox = {
      source  = "jackby03/hardbox"
      version = "~> 0.3"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

provider "hardbox" {
  hardbox_version = "latest"
}

# ── Compute Engine VM ─────────────────────────────────────────────────────────

resource "google_compute_instance" "web" {
  name         = "hardbox-demo"
  machine_type = "e2-medium"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    network    = "default"
    subnetwork = var.subnetwork
    # No external IP — access via IAP TCP tunnel
  }

  service_account {
    email  = var.service_account_email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  tags = ["hardbox-demo"]
}

# ── hardbox hardening ─────────────────────────────────────────────────────────

resource "hardbox_apply" "web" {
  # Use internal IP; access via IAP TCP tunnel or private network
  host        = google_compute_instance.web.network_interface[0].network_ip
  user        = "ubuntu"
  private_key = file(var.private_key_path)

  profile       = "cloud-gcp"
  report_format = "json"

  fail_on_critical    = true
  fail_on_high        = true
  rollback_on_failure = true

  depends_on = [google_compute_instance.web]
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "instance_name" {
  value = google_compute_instance.web.name
}

output "hardbox_applied_at" {
  value = hardbox_apply.web.applied_at
}

output "hardbox_findings" {
  value = hardbox_apply.web.findings
}
