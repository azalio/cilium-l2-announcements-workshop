#!/bin/bash

# Установка kubectl
curl -LO "https://dl.k8s.io/release/v1.32.1/bin/linux/arm64/kubectl"
install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Копирование конфигурации с control plane
mkdir -p /root/.kube
scp root@server:/etc/kubernetes/admin.conf /root/.kube/config
chmod 600 /root/.kube/config

# Установка утилит для управления
apt-get install -y bash-completion
echo 'source <(kubectl completion bash)' >> /root/.bashrc
