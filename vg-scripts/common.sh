#!/bin/bash
#
# Kubernetes Node Setup Script
#
# Purpose: Prepares system environment for Kubernetes cluster nodes by configuring:
# - System requirements validation
# - Network stack and kernel parameters
# - Container runtime dependencies
# - Security settings and firewall rules
# - SSH access for cluster communication
#
# This script is part of the "Kubernetes The Hard Way" tutorial series
# and demonstrates core system configurations needed for a production-ready
# Kubernetes cluster.
#
# Usage: ./common.sh
#
# System Requirements:
#   Base System:
#   - Debian-based Linux distribution
#   - Root privileges for system configuration
#   
#   Kubernetes Nodes:
#   - RAM: 1900MB minimum (for kubelet, container runtime, pods)
#   - CPU: 2 cores (required for control plane components)
#   - Disk: 20GB (for OS, container images, and pod storage)
#
# Network Ports:
#   Control Plane:
#   - 6443: Kubernetes API Server
#   - 2379-2380: etcd server client API
#   - 10250: Kubelet API
#   - 10251: kube-scheduler
#   - 10252: kube-controller-manager
#
#   Worker Nodes:
#   - 10250: Kubelet API
#   - 30000-32767: NodePort Services Range
#
# Author: Mikhail [azalio] Petrov
# Date: 2024
# Version: 1.0

# Подключение вспомогательных функций
source /vagrant/vg-scripts/utils.sh

# Exit codes
readonly E_GENERAL=1
readonly E_PREREQ=2
readonly E_NETWORK=3
readonly E_PACKAGE=4

# Node type detection
readonly NODE_TYPE=$(hostname)

# Resource requirements by node type
readonly NODE_RAM_KB=1945600      # 1900MB in KB (binary)
readonly NODE_DISK_KB=20971520    # 20GB in KB

# Error handling
set -euo pipefail
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

# Logging setup
exec 1> >(tee -a /var/log/k8s-setup.log) 2>&1


check_prerequisites() {
    log "Validating system requirements for Kubernetes node type: ${NODE_TYPE}"
    
    # Пропустить проверку для jumpbox
    if [[ "${NODE_TYPE}" == "jumpbox" ]]; then
        log "Skipping resource validation for jumpbox"
        return 0
    fi

    # Определение требований к ресурсам в зависимости от роли узла
    local required_ram_kb=$NODE_RAM_KB
    local required_disk_kb=$NODE_DISK_KB
    
    # Проверка RAM
    local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [[ ${ram_kb} -lt ${required_ram_kb} ]]; then
        echo "Insufficient RAM. Required: $((required_ram_kb/1024))MB, Found: $((ram_kb/1024))MB"
        exit $E_PREREQ
    fi
    
    # Проверка Disk Space
    local disk_kb=$(df -k / | tail -1 | awk '{print $4}')
    if [[ ${disk_kb} -lt ${required_disk_kb} ]]; then
        echo "Insufficient disk space. Required: $((required_disk_kb/1024/1024))GB, Found: $((disk_kb/1024/1024))GB"
        exit $E_PREREQ
    fi
}

# Start execution
log "Starting Kubernetes node setup..."
check_prerequisites

# Add Kubernetes repo for v1.32.1
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list

# Update package lists after adding new repo
if ! apt-get update -y; then
    log "ERROR: Failed to update package lists"
    exit $E_PACKAGE
fi

log "Installing required packages..."

PACKAGES=(
    software-properties-common
    curl
    apt-transport-https
    ca-certificates
    gnupg
    lsb-release
    iptables
    wget 
    vim 
    atop 
    tmux 
    iftop 
    net-tools
    openssl
    git
    socat
    conntrack
    ipset
    bridge-utils
    tcpdump
    kubelet=1.32.1-1.1
    kubeadm=1.32.1-1.1
    kubectl=1.32.1-1.1
    containerd
    cri-tools
    arping
)

if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"; then
    log "ERROR: Failed to install required packages"
    exit $E_PACKAGE
fi

# Установка openssh-server отдельно с отложенным перезапуском
log "Installing openssh-server..."
if ! DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server; then
    log "ERROR: Failed to install openssh-server"
    exit $E_PACKAGE
fi

# Hold Kubernetes packages at specific version
apt-mark hold kubelet kubeadm kubectl

cat >> /etc/hosts <<EOF
192.168.56.20 server.kubernetes.local server
192.168.56.50 node-0.kubernetes.local node-0
192.168.56.60 node-1.kubernetes.local node-1
EOF

log "Disabling swap..."
swapoff -a
sed -i '/swap/d' /etc/fstab

log "Configuring kernel modules required for Kubernetes..."
# Create configuration for required kernel modules
cat > /etc/modules-load.d/k8s.conf <<EOF
# Overlay network for container runtime
overlay

# Bridge networking for container communication
br_netfilter

# IP Virtual Server (IPVS) for service load balancing
ip_vs
ip_vs_rr        # Round-Robin scheduling
ip_vs_wrr       # Weighted Round-Robin scheduling
ip_vs_sh        # Source Hashing scheduling

# Connection tracking for network filtering
nf_conntrack
EOF

# Load kernel modules
for module in overlay br_netfilter ip_vs ip_vs_rr ip_vs_wrr ip_vs_sh nf_conntrack; do
    if ! modprobe $module; then
        log "ERROR: Failed to load kernel module: $module"
        exit $E_GENERAL
    fi
done

log "Configuring kernel parameters for Kubernetes networking and performance..."
cat > /etc/sysctl.d/k8s.conf <<EOF
# Kubernetes Container Networking Requirements
# Enable iptables processing of bridged traffic
net.bridge.bridge-nf-call-iptables  = 1    # Required for containers to reach outside network
net.bridge.bridge-nf-call-ip6tables = 1    # IPv6 support
net.ipv4.ip_forward                 = 1    # Required for container communication

# Network Performance Tuning
# Increase system and backlog connection limits
net.core.somaxconn = 32768                 # Maximum socket connection queue
net.ipv4.tcp_max_syn_backlog = 32768      # Maximum SYN backlog
net.core.netdev_max_backlog = 32768       # Maximum network interface backlog
net.ipv4.tcp_timestamps = 1               # Better round-trip time estimation
net.ipv4.tcp_tw_reuse = 1                # Reuse sockets in TIME-WAIT state

# Connection Tracking for Kubernetes Services
net.netfilter.nf_conntrack_max = 1048576  # Maximum tracked connections
net.nf_conntrack_max = 1048576            # Legacy support
net.netfilter.nf_conntrack_tcp_timeout_established = 86400  # Timeout for established connections

# System Resource Limits
fs.inotify.max_user_watches = 524288      # Required for kubectl and container monitoring
fs.file-max = 2097152                     # Maximum number of file handles
EOF

sysctl --system || {
    log "ERROR: Failed to apply sysctl parameters"
    exit $E_GENERAL
}


log "Configuring ssh access..."
sed -i \
  's/^#PermitRootLogin.*/PermitRootLogin yes/' \
  /etc/ssh/sshd_config

# if [[ "${NODE_TYPE}" == "jumpbox" ]]; then

echo 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFB
QUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFB
d0VBQVFBQUFZRUEvUUFkN0phNlVmMGl6SFRNeHkyTzIxN05IUTFaMmJ6bkZtMld3Y054alRTSGdH
RWZuZUpXCnBpeFd0eGJhY3RFNVZvTlVwT2FKMHExVFhVWW13VVFPK2s0V0ZyMEpmS1JPZHlIdEds
cWlnUUw3RUNjUE9kaXZvUGtPajcKUFA2NlZiSlh3bHRNWDkveVZJK3FYeE1CRy8xZUppUVI3NThQ
WExPSmgwNVNqU1RsVzR4UGVHYVF4SjlsYUF5dG0vbCtBZAoydTZwNnIzdjMrbmducVU5a0ZRVXpo
L2lTRDRDemFJclF5Z3hSVjhPRXQ4Vlp0b1JONlBwdW5ZNUlseHJYVXlVRmthUENHCmFmSzRpWkhx
MEJSNnVXTzc2OHYrZTRpL1pJR2pCeUxacFJhVXlSMThSWUhPOVNoSDR4dURZUmlmMHlNNGx1RE5Q
eFgxUUgKQmlHUHQxVm1jYWQyMjhvNVRJa0tBZmxGa2kxUTRaMm5TYy8ycVJTdWI3VlpzVUhqN0tP
M293T1lCRjhsR3RzdkJBV01jYgpONTlSUGthWkN0YVhubWw5eU5vN0lnKzNIQzBaK3RaQ2U4aHBw
RXAreTlLZEc2V3lsdGtERUJ5M0NLRi81N0s0a1BVLy9YCjZmdGVhYVEweDVaaE9OWVNOTWNmdEkx
ajF5M3BxanRkc2ZReVZUTGZBQUFGZ0gyNkwzcDl1aTk2QUFBQUIzTnphQzF5YzIKRUFBQUdCQVAw
QUhleVd1bEg5SXN4MHpNY3RqdHRlelIwTldkbTg1eFp0bHNIRGNZMDBoNEJoSDUzaVZxWXNWcmNX
Mm5MUgpPVmFEVktUbWlkS3RVMTFHSnNGRUR2cE9GaGE5Q1h5a1RuY2g3UnBhb29FQyt4QW5Eem5Z
cjZENURvK3p6K3VsV3lWOEpiClRGL2Y4bFNQcWw4VEFSdjlYaVlrRWUrZkQxeXppWWRPVW8wazVW
dU1UM2hta01TZlpXZ01yWnY1ZmdIZHJ1cWVxOTc5L3AKNEo2bFBaQlVGTTRmNGtnK0FzMmlLME1v
TVVWZkRoTGZGV2JhRVRlajZicDJPU0pjYTExTWxCWkdqd2htbnl1SW1SNnRBVQplcmxqdSt2TC9u
dUl2MlNCb3djaTJhVVdsTWtkZkVXQnp2VW9SK01iZzJFWW45TWpPSmJnelQ4VjlVQndZaGo3ZFZa
bkduCmR0dktPVXlKQ2dINVJaSXRVT0dkcDBuUDlxa1VybSsxV2JGQjQreWp0Nk1EbUFSZkpScmJM
d1FGakhHemVmVVQ1R21RclcKbDU1cGZjamFPeUlQdHh3dEdmcldRbnZJYWFSS2ZzdlNuUnVsc3Bi
WkF4QWN0d2loZitleXVKRDFQLzErbjdYbW1rTk1lVwpZVGpXRWpUSEg3U05ZOWN0NmFvN1hiSDBN
bFV5M3dBQUFBTUJBQUVBQUFHQURub3oxY05uNGFQOW1tSHIyRkVvRXBYdVlOCkkyajIxVWN4K0JF
WkVEdXFDZDRzWXNBbU40U3hKcURrdW9zQXArN1VLZkIvTUlkU3BsaFFhc0NYVW9KWFNnY282bkZv
WFIKUFQwb3dOQlFIWEZubjBZQUhneEpvaU1YODU1Z1NoaTlQWHdWeHE0MmpOYnZLRm8rSzVITzJE
dGt0c0dvYkMrbnM1TXR5NgpUUHdtZ3ZXWXJjZ1l1UXJZWXVGQ0M1VVBlOWtOQ2ZCYnJEZjlBUFR3
c2ZtYnpsL0s1Z1pLNU1oL2R3U0ZJZGQ2cVJhak52CnpLNnpDRkpCRTN2WC9sUDM4YU1EM1RleHNF
TEZxaER3aDl2QnFaUUExdEJCZWdxTTcyNjJDSnhKWUQ4dVFyeWV6cThNVGEKZlVPK1pwYzYzV1hF
R1VzdVJvQkJqVDlSaGg3UnlqLzRHN2dDYnBqa2hub3ZnSStjampYQWFWbEMxWk9TWTNOMHE1d2N6
Vgp2cGxMZ2pFUGNZMmt6K2k1RG43U3FkenUvcm9UNFB5ZWRDMGNIVDViR04rMkRnb3A0dVZGeCtI
Y3d5K2tPVnE2ajFSRUVVClJ6RENjS1RieEtqdjFROTZLRGZ0R1NVb25RelNFOE5EY2NwRnI1S1FK
Y3ZLUG9RVVBxbnlhVkN0cmo0WkY0U2dqQkFBQUEKd0JpaVI4Z1NRdEJoQlJSS0x2YkZzUnpnVWpV
cE5tWWdTekVzNXZIMlBYM0xhbzRSNzZyY0hqRDZySnNOZ1pMTkpvVi9JNAp6WkpubDh2VGpsWHlO
RWg5UW5yZlRrZjU0b2gwalFEcEtQZ29IT2ZtajFxYk5DZHBpRCs5VUJocnZqMEhIN04rMFRrMkpt
CnlZWndNeTcvSWM2ajF5aDJWVFZvOHVSd3hUbEJ6ZG1zQkt1RDEyaFFLUWFxWGpaWW1vaWNSd3hD
djIzWVNoanhnTWt3Q3EKdUhoOW5vNmlUeUh3dW9vZnB0UU4xMlBSVFByWVRMZ051T0pSV1AyS0du
Yk8xQWdnQUFBTUVBL3ovL29DNUVKVStJY0hMYwpyNUM2cXpIcEowSWM0azhrU1Y3NGpMNWZDWHAr
Vm9TUDQyTlplYjNVOW1zaUw2eVVMK1Vzei9mTkVkbXg3cW41M2hkM1p1CldRc2tYenhNaENNeXg5
SDl0YXZlbm91eWE0Tk82QkZzQzN6WlRGd1MzTzAvVDdKVWVYZ0hzbGdsMW1iKzR4MXVEV1cvSysK
R2d5SUF2S2JJT1RkbnZreEgzZFNtTnhXeVpqQjNZT1E2dHBmMkRCVDUySmNMYWVsdnFOVk1paFNT
UFNIWXBqZDFGbCswTApmZmJ0d0VINEEyR1NnazdicHgvT0dsT29hbFdlSGhBQUFBd1FEOXZtMGRa
bFE1QXFWbUJyU1F1bCtnQ2hIRGZLYmZabWlNCld4dWlmSjN3UmZhYjNqRzJIaVVvalVxTlIxazFi
Zmt4NnJIa1dOcko0bTZhR1BjZEJLa2JqSnNJUDN0THlURzhyYmFtUWkKM0RSMXMyMkVzUHRmMkhD
SitpWm9OTlp6Q0M2UmtJRGVPeDhxRENBSE1WM01BSnZidzd3K1dDeUpZb3o5eXZESFBTN0h6NQpi
MWhjVTJ5cEU0bkczNEFNMm1wMUxZeTVwNllQdGVyMTBySC85NitJZ0pFMzl3K1FQd0d3MUl2ZHBF
NkNkREVValBnSllsCng2aHNQT3p0WFRMTDhBQUFBTGNtOXZkRUJ6WlhKMlpYST0KLS0tLS1FTkQg
T1BFTlNTSCBQUklWQVRFIEtFWS0tLS0tCg==' | base64 -d > /root/.ssh/id_rsa

chmod 600 /root/.ssh/id_rsa

# Disable key checking because it is test env
cat << EOF > /root/.ssh/config
Host *
    StrictHostKeyChecking no
EOF


# else

echo 'c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FEOUFCM3NscnBSL1NMTWRNekhM
WTdiWHMwZERWblp2T2NXYlpiQnczR05OSWVBWVIrZDRsYW1MRmEzRnRweTBUbFdnMVNrNW9uU3JW
TmRSaWJCUkE3NlRoWVd2UWw4cEU1M0llMGFXcUtCQXZzUUp3ODUySytnK1E2UHM4L3JwVnNsZkNX
MHhmMy9KVWo2cGZFd0ViL1Y0bUpCSHZudzljczRtSFRsS05KT1ZiakU5NFpwREVuMlZvREsyYitY
NEIzYTdxbnF2ZS9mNmVDZXBUMlFWQlRPSCtKSVBnTE5vaXRES0RGRlh3NFMzeFZtMmhFM28rbTZk
amtpWEd0ZFRKUVdSbzhJWnA4cmlKa2VyUUZIcTVZN3ZyeS81N2lMOWtnYU1ISXRtbEZwVEpIWHhG
Z2M3MUtFZmpHNE5oR0ovVEl6aVc0TTAvRmZWQWNHSVkrM1ZXWnhwM2JieWpsTWlRb0IrVVdTTFZE
aG5hZEp6L2FwRks1dnRWbXhRZVBzbzdlakE1Z0VYeVVhMnk4RUJZeHhzM24xRStScGtLMXBlZWFY
M0kyanNpRDdjY0xSbjYxa0o3eUdta1NuN0wwcDBicGJLVzJRTVFITGNJb1gvbnNyaVE5VC85ZnAr
MTVwcERUSGxtRTQxaEkweHgrMGpXUFhMZW1xTzEyeDlESlZNdDg9IHJvb3RAc2VydmVyCg==' | base64 -d >> /root/.ssh/authorized_keys

# fi

systemctl restart sshd

log "Configuring firewall rules..."

sysctl -w net.ipv4.ip_forward=1

# Enable ARP proxying for eth1
# log "Enabling ARP proxying on eth1..."
# echo 1 > /proc/sys/net/ipv4/conf/eth1/proxy_arp
# echo "echo 1 > /proc/sys/net/ipv4/conf/eth1/proxy_arp" >> /etc/rc.local
# chmod +x /etc/rc.local
# log "ARP proxying enabled on eth1"

log "Configuring containerd to use correct pause image and enable SystemdCgroup..."

# Create or update containerd configuration
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml

# Update pause image to version 3.10
sed -i 's|registry.k8s.io/pause:3.6|registry.k8s.io/pause:3.10|g' /etc/containerd/config.toml

# Enable SystemdCgroup
sed -i 's|SystemdCgroup = false|SystemdCgroup = true|' /etc/containerd/config.toml

# Restart containerd to apply changes
systemctl restart containerd

log "Containerd configured with pause image: registry.k8s.io/pause:3.10 and SystemdCgroup enabled"
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

if [[ "${NODE_TYPE}" == "server" ]]; then
    # Allow required ports for control plane
    iptables -A INPUT -p tcp --dport 6443 -j ACCEPT  # Kubernetes API server
    iptables -A INPUT -p tcp --dport 2379:2380 -j ACCEPT  # etcd server client API
    iptables -A INPUT -p tcp --dport 10250 -j ACCEPT  # Kubelet API
    iptables -A INPUT -p tcp --dport 10251 -j ACCEPT  # kube-scheduler
    iptables -A INPUT -p tcp --dport 10252 -j ACCEPT  # kube-controller-manager
elif [[ "${NODE_TYPE}" == "node0" || "${NODE_TYPE}" == "node1" ]]; then
    # Allow required ports for worker nodes
    iptables -A INPUT -p tcp --dport 10250 -j ACCEPT  # Kubelet API
    iptables -A INPUT -p tcp --dport 30000:32767 -j ACCEPT  # NodePort Services
fi

if [[ "${NODE_TYPE}" == "jumpbox" ]]; then
log "Configuring machines.txt..."

cat << EOF > /root/machines.txt
192.168.56.20 server.kubernetes.local server
192.168.56.50 node-0.kubernetes.local node-0 10.200.0.0/24
192.168.56.60 node-1.kubernetes.local node-1 10.200.1.0/24
EOF

fi

log "Configuring pod network routes..."

# Определение подсети для каждого узла
case "${NODE_TYPE}" in
    "server")
        POD_SUBNET="10.200.0.0/24"
        ;;
    "node-0")
        POD_SUBNET="10.200.1.0/24"
        ;;
    "node-1")
        POD_SUBNET="10.200.2.0/24"
        ;;
    "jumpbox")
        # Для jumpbox не требуется подсеть для подов
        log "Skipping pod network routes configuration for jumpbox"
        exit 0
        ;;
    *)
        log "Unknown node type: ${NODE_TYPE}"
        exit 1
        ;;
esac

# Настройка маршрутов для других узлов
if [[ "${NODE_TYPE}" == "server" ]]; then
    ip route add 10.200.1.0/24 via 192.168.56.50
    ip route add 10.200.2.0/24 via 192.168.56.60
elif [[ "${NODE_TYPE}" == "node-0" ]]; then
    ip route add 10.200.0.0/24 via 192.168.56.20
    ip route add 10.200.2.0/24 via 192.168.56.60
elif [[ "${NODE_TYPE}" == "node-1" ]]; then
    ip route add 10.200.0.0/24 via 192.168.56.20
    ip route add 10.200.1.0/24 via 192.168.56.50
fi

# # Сохранение маршрутов в конфигурацию сети
# cat <<EOF > /etc/network/interfaces.d/90-pod-routes
# # Pod network routes
# up ip route add 10.200.0.0/24 via 192.168.56.20 || true
# up ip route add 10.200.1.0/24 via 192.168.56.50 || true
# up ip route add 10.200.2.0/24 via 192.168.56.60 || true
# EOF

# log "Pod network routes configured successfully"

log "Configuring crictl for containerd..."

# Create crictl configuration file
cat > /etc/crictl.yaml <<EOF
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
debug: false
EOF

log "crictl configured successfully"

log "Successfully completed Kubernetes node setup"
