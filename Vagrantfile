# -*- mode: ruby -*-
# vi: set ft=ruby :

# Kubernetes The Hard Way - Vagrant Configuration
# Purpose: Creates a multi-node Kubernetes cluster environment using VMware provider
# Components:
#   - Server (192.168.56.20): Kubernetes control plane
#   - Node-0 (192.168.56.50): Worker node
#   - Node-1 (192.168.56.60): Worker node
#
# Requirements:
#   - Vagrant 2.3+
#   - VMware Desktop provider
#   - Minimum 8GB RAM available
#   - ARM64 architecture support
#
# Author: Mikhail [azalio] Petrov
# Date: 2025
# Version: 1.0

# Validate requirements
raise 'VMware Desktop provider required' unless Vagrant.has_plugin?('vagrant-vmware-desktop')

# Configuration Variables
NETWORK_PREFIX = "192.168.56"
VM_SETTINGS = {
  'server'  => { memory: 2048, cpus: 2, ip: "#{NETWORK_PREFIX}.20" },  # Increased CPUs from 1 to 2
  'node-0'  => { memory: 2048, cpus: 1, ip: "#{NETWORK_PREFIX}.50" },
  'node-1'  => { memory: 2048, cpus: 1, ip: "#{NETWORK_PREFIX}.60" }
}

Vagrant.require_version ">= 2.3.0"

Vagrant.configure("2") do |config|
  # Base box configuration
  config.vm.box = "bento/debian-12.5-arm64"
  config.vm.box_version = "202404.23.0"
  config.vm.box_check_update = false
  
  # Default provider settings
  config.vm.provider "vmware_desktop" do |vmware|
    vmware.gui = false
    vmware.vmx["ethernet0.virtualDev"] = "vmxnet3"
    vmware.vmx["memsize"] = "1024"
    vmware.vmx["numvcpus"] = "1"
    vmware.vmx["security.allowGuestConnectionControl"] = "false"
    vmware.vmx["isolation.tools.copy.disable"] = "true"
    vmware.vmx["isolation.tools.paste.disable"] = "true"
  end

  # SSH configuration
  config.ssh.forward_agent = true
  config.ssh.insert_key = true
  config.ssh.keys_only = true

  # Common configuration script
  config.vm.provision "shell", path: "vg-scripts/common.sh"


  config.vm.define "server" do |server|
    server.vm.hostname = "server"
    server.vm.provider "vmware_desktop" do |vmware|
      vmware.memory = VM_SETTINGS['server'][:memory]
      vmware.cpus = 2  # Increased from 1 to 2 for Kubernetes control plane requirements
    end
    server.vm.network "private_network", 
      ip: VM_SETTINGS['server'][:ip],
      netmask: "255.255.255.0",
      auto_config: true,
      virtualbox__intnet: true
    
    server.vm.provision "shell", path: "vg-scripts/control-plane-setup.sh"
  end
  
  # Worker nodes configuration
  ["node-0", "node-1"].each_with_index do |node_name, index|
    config.vm.define node_name do |node|
      node.vm.hostname = node_name
      node.vm.provider "vmware_desktop" do |vmware|
        vmware.memory = VM_SETTINGS[node_name][:memory]
        vmware.cpus = VM_SETTINGS[node_name][:cpus]
      end
      node.vm.network "private_network",
        ip: VM_SETTINGS[node_name][:ip],
        netmask: "255.255.255.0",
        auto_config: true,
        virtualbox__intnet: true

      node.vm.provision "shell", path: "vg-scripts/worker-node-setup.sh"
    end
  end
end
