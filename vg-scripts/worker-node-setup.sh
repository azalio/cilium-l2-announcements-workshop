#!/bin/bash

# Установка зависимостей
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg

# Добавление репозитория Kubernetes
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list

# Установка kubeadm и kubelet
apt-get update
apt-get install -y kubelet=1.32.1-1.1 kubeadm=1.32.1-1.1
apt-mark hold kubelet kubeadm

# Получение команды для присоединения к кластеру
JOIN_COMMAND=$(ssh -o StrictHostKeyChecking=no root@server "kubeadm token create --print-join-command")

# Присоединение к кластеру
$JOIN_COMMAND
