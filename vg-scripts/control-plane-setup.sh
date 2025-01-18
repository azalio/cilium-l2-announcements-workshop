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
#!/bin/bash

# Создание конфигурационного файла для kubeadm
cat <<EOF > /root/kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
bootstrapTokens:
- token: "9a08jv.c0izixklcxtmnze7"
  description: "kubeadm bootstrap token"
  ttl: "24h"
nodeRegistration:
  name: "server"
  criSocket: "/var/run/containerd/containerd.sock"
  kubeletExtraArgs:
    node-ip: "192.168.56.20"
localAPIEndpoint:
  advertiseAddress: "192.168.56.20"
  bindPort: 6443
skipPhases:
  - addon/kube-proxy  # Пропуск установки kube-proxy
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
etcd:
  local:
    dataDir: "/var/lib/etcd"
    extraArgs:
      listen-client-urls: "http://192.168.56.20:2379"
      advertise-client-urls: "http://192.168.56.20:2379"
networking:
  serviceSubnet: "10.96.0.0/16"
  podSubnet: "10.244.0.0/16"
  dnsDomain: "cluster.local"
kubernetesVersion: "v1.32.1"
controlPlaneEndpoint: "192.168.56.20:6443"
apiServer:
  extraArgs:
    advertise-address: "192.168.56.20"
  certSANs:
    - "192.168.56.20"
    - "server.kubernetes.local"
controllerManager:
  extraArgs:
    node-cidr-mask-size: "24"
scheduler:
  extraArgs:
    bind-address: "192.168.56.20"
certificatesDir: "/etc/kubernetes/pki"
imageRepository: "registry.k8s.io"
EOF

# Инициализация control-plane с использованием конфигурационного файла
kubeadm init --config=/root/kubeadm-config.yaml

# Настройка kubectl для пользователя root
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown root:root /root/.kube/config
