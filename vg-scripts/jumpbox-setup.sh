#!/bin/bash

# Функция для логирования
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Установка kubectl
apt-get update
apt-get install -y kubectl=1.32.1-1.1

# Создание директории .kube
mkdir -p /root/.kube

log "Jumpbox setup completed successfully. Please run the following command after server is ready:"
log "scp root@server:/etc/kubernetes/admin.conf /root/.kube/config && chmod 600 /root/.kube/config"

# Установка утилит для управления
apt-get install -y bash-completion
echo 'source <(kubectl completion bash)' >> /root/.bashrc
