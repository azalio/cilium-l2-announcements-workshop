#!/bin/bash

# Ensure packages are up to date
apt-get update
# apt-get upgrade -y

# Инициализация кластера (без kube-proxy)
kubeadm init --skip-phases=addon/kube-proxy

# Настройка доступа для root
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config
