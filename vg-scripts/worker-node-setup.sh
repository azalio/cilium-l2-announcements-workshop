#!/bin/bash

# Ensure packages are up to date
# apt-get update
# apt-get upgrade -y

# Получение команды для присоединения к кластеру
JOIN_COMMAND=$(ssh -o StrictHostKeyChecking=no root@server "kubeadm token create --print-join-command")

# Присоединение к кластеру
$JOIN_COMMAND

# Копирование конфигурации Kubernetes на сервер
# log "Copying Kubernetes config to server..."
# scp /root/.kube/config root@server:/root/.kube/config_node_$(hostname)
# ssh root@server "chmod 600 /root/.kube/config_node_$(hostname)"
