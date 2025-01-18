#!/bin/bash

# Установка зависимостей
apt-get update
apt-get install -y apt-transport-https ca-certificates curl gnupg

# Добавление репозитория Kubernetes
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list

# Установка kubeadm, kubelet и kubectl
apt-get update
apt-get install -y kubelet=1.32.1-1.1 kubeadm=1.32.1-1.1 kubectl=1.32.1-1.1
apt-mark hold kubelet kubeadm kubectl

# Инициализация кластера (без kube-proxy)
kubeadm init --skip-phases=addon/kube-proxy

# Настройка доступа для root
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config
