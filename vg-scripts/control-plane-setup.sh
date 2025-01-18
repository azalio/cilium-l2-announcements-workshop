#!/bin/bash

# Подключение вспомогательных функций
source /vagrant/vg-scripts/utils.sh

# Ensure packages are up to date
# apt-get update

# Создание конфигурационного файла для kubeadm
cat <<EOF > /root/kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta4
bootstrapTokens:
- description: kubeadm bootstrap token
  groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: 9a08jv.c0izixklcxtmnze7
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: 192.168.56.20
  bindPort: 6443
nodeRegistration:
  criSocket: unix:///var/run/containerd/containerd.sock
  imagePullPolicy: IfNotPresent
  imagePullSerial: true
  kubeletExtraArgs:
  - name: node-ip
    value: 192.168.56.20
  name: server
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/control-plane
skipPhases:
- addon/kube-proxy
timeouts:
  controlPlaneComponentHealthCheck: 4m0s
  discovery: 5m0s
  etcdAPICall: 2m0s
  kubeletHealthCheck: 4m0s
  kubernetesAPICall: 1m0s
  tlsBootstrap: 5m0s
  upgradeManifests: 5m0s
---
apiServer:
  certSANs:
  - 192.168.56.20
  - server.kubernetes.local
  extraArgs:
  - name: advertise-address
    value: 192.168.56.20
apiVersion: kubeadm.k8s.io/v1beta4
caCertificateValidityPeriod: 87600h0m0s
certificateValidityPeriod: 8760h0m0s
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controlPlaneEndpoint: 192.168.56.20:6443
controllerManager:
  extraArgs:
    - name: "allocate-node-cidrs"
      value: "false"
    - name: "cluster-cidr"
      value: ""
dns: {}
encryptionAlgorithm: RSA-2048
etcd:
  local:
    dataDir: /var/lib/etcd
    extraArgs:
    - name: advertise-client-urls
      value: https://192.168.56.20:2379
    - name: listen-client-urls
      value: https://192.168.56.20:2379
imageRepository: registry.k8s.io
kind: ClusterConfiguration
kubernetesVersion: v1.32.1
networking:
  dnsDomain: cluster.local
  podSubnet: 10.200.0.0/24
  serviceSubnet: 10.96.0.0/16
proxy: {}
scheduler:
  extraArgs:
  - name: bind-address
    value: 192.168.56.20
EOF

# Инициализация control-plane с использованием конфигурационного файла
kubeadm init --config=/root/kubeadm-config.yaml

# Настройка kubectl для пользователя root
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config

# Configure podCIDR for the server node
kubectl --kubeconfig=/etc/kubernetes/kubelet.conf patch node server --type merge -p '{"spec":{"podCIDR":"10.200.0.0/24"}}'

log "Configured podCIDR for server node"

log "Installing Helm..."

# Download Helm installation script
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3

# Make the script executable
chmod 700 get_helm.sh

# Run the installation script
./get_helm.sh

# Clean up
rm get_helm.sh

log "Helm installed successfully"

# Install Cilium CNI
helm repo add cilium https://helm.cilium.io/
helm upgrade --install cilium cilium/cilium --version 1.16.5 --namespace kube-system \
  --set l2announcements.enabled=true \
  --set kubeProxyReplacement=true \
  --set ipam.mode=kubernetes \
  --set k8sServiceHost=192.168.56.20 \
  --set k8sServicePort=6443 \
  --set operator.replicas=1 \
  --set routingMode=native \
  --set ipv4NativeRoutingCIDR=10.200.0.0/22 \
  --set endpointRoutes.enabled=true

log "Cilium installed successfully"
