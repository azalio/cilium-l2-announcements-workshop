#!/bin/bash

# Установка kubectl
apt-get update
apt-get install -y kubectl=1.32.1-1.1

# Ожидание готовности сервера и копирование конфигурации
mkdir -p /root/.kube
log "Ожидание готовности сервера..."

# Проверяем доступность сервера и наличие конфигурации
while true; do
    if ssh -o ConnectTimeout=5 root@server "test -f /etc/kubernetes/admin.conf"; then
        log "Сервер готов, копируем конфигурацию..."
        scp root@server:/etc/kubernetes/admin.conf /root/.kube/config
        chmod 600 /root/.kube/config
        break
    else
        log "Сервер еще не готов, повторная попытка через 10 секунд..."
        sleep 10
    fi
done

# Установка утилит для управления
apt-get install -y bash-completion
echo 'source <(kubectl completion bash)' >> /root/.bashrc
