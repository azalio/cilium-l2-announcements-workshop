#!/bin/bash

# Подключение вспомогательных функций
source /vagrant/vg-scripts/utils.sh

# Ensure packages are up to date
# apt-get update
# apt-get upgrade -y


# Получение команды для присоединения к кластеру
JOIN_COMMAND=$(ssh -o StrictHostKeyChecking=no root@server "kubeadm token create --print-join-command")

# Присоединение к кластеру
$JOIN_COMMAND

# Configure podCIDR for worker nodes
if [[ $(hostname) == "node-0" ]]; then
  kubectl --kubeconfig=/etc/kubernetes/kubelet.conf patch node node-0 --type merge -p '{"spec":{"podCIDR":"10.200.1.0/24"}}'
  log "Configured podCIDR for node-0"
elif [[ $(hostname) == "node-1" ]]; then
  kubectl --kubeconfig=/etc/kubernetes/kubelet.conf patch node node-1 --type merge -p '{"spec":{"podCIDR":"10.200.2.0/24"}}'
  log "Configured podCIDR for node-1"
fi

# Install network routes script
log "Configuring network routes for eth1 interface..."
cp /vagrant/vg-scripts/add-routes.sh /etc/network/if-up.d/add-routes
chmod +x /etc/network/if-up.d/add-routes
log "Network routes script installed"
