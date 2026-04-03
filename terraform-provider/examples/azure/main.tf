terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    hardbox = {
      source  = "jackby03/hardbox"
      version = "~> 0.3"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "hardbox" {
  hardbox_version = "latest"
}

# ── Azure VM ──────────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "rg" {
  name     = "hardbox-demo-rg"
  location = var.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = "hardbox-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "hardbox-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_interface" "nic" {
  name                = "hardbox-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                = "hardbox-demo"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_B2s"
  admin_username      = "azureuser"

  network_interface_ids = [azurerm_network_interface.nic.id]

  admin_ssh_key {
    username   = "azureuser"
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }
}

# ── hardbox hardening ─────────────────────────────────────────────────────────

resource "hardbox_apply" "vm" {
  host        = azurerm_network_interface.nic.private_ip_address
  user        = "azureuser"
  private_key = file(var.ssh_private_key_path)

  profile       = "cloud-azure"
  report_format = "json"

  fail_on_critical    = true
  fail_on_high        = true
  rollback_on_failure = true

  depends_on = [azurerm_linux_virtual_machine.vm]
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "vm_name" {
  value = azurerm_linux_virtual_machine.vm.name
}

output "hardbox_applied_at" {
  value = hardbox_apply.vm.applied_at
}

output "hardbox_findings" {
  value = hardbox_apply.vm.findings
}
