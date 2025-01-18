#!/bin/bash

# Установка kubectl
apt-get update
apt-get install -y kubectl=1.32.1-1.1

# Копирование конфигурации с control plane
mkdir -p /root/.kube
scp root@server:/etc/kubernetes/admin.conf /root/.kube/config
chmod 600 /root/.kube/config

# Установка утилит для управления
apt-get install -y bash-completion
echo 'source <(kubectl completion bash)' >> /root/.bashrc
