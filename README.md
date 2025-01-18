# Kubernetes Cluster Setup with Vagrant and kubeadm

Этот проект предоставляет автоматизированную настройку локального Kubernetes-кластера с использованием Vagrant, VMware и `kubeadm`. Кластер состоит из одного control-plane узла и двух worker-узлов, настроенных для работы в изолированной сети.

## Основные компоненты

- **Control Plane (server)**:
  - IP: `192.168.56.20`
  - Роли: API Server, Scheduler, Controller Manager, etcd
  - Ресурсы: 2 CPU, 2GB RAM

- **Worker Nodes (node-0, node-1)**:
  - IP: `192.168.56.50` (node-0), `192.168.56.60` (node-1)
  - Роли: Запуск рабочих нагрузок (поды)
  - Ресурсы: 1 CPU, 2GB RAM

## Особенности проекта

- **Поддержка ARM64**: Используется образ `bento/debian-12.5-arm64`.
- **Изолированная сеть**: Все узлы находятся в одной подсети `192.168.56.0/24`.
- **Подсети для подов**: Каждому узлу выделена своя подсеть `/24`:
  - `10.200.0.0/24` для server
  - `10.200.1.0/24` для node-0
  - `10.200.2.0/24` для node-1
- **Маршрутизация между узлами**: Настроены статические маршруты для связи между подсетями подов.
- **SystemdCgroup**: Включен в конфигурации `containerd` для поддержки cgroups v2.
- **Использование kubeadm**: Упрощенная установка Kubernetes с помощью `kubeadm`.

## Сетевой плагин (CNI)

Для сетевого взаимодействия между подами используется **Cilium** с включенными L2-анонсами и заменой kube-proxy. Основные параметры конфигурации:

- **IPAM**: Kubernetes (использует `spec.podCIDR` для выделения IP-адресов).
- **L2-анонсы**: Включены для поддержки L2-коммуникации.
- **Замена kube-proxy**: Включена для повышения производительности.
- **Подсети для подов**:
  - `10.200.0.0/24` для server
  - `10.200.1.0/24` для node-0
  - `10.200.2.0/24` для node-1

## Требования

- **Vagrant 2.3+**
- **VMware Desktop Provider**
- **Минимум 8GB RAM**
- **Поддержка ARM64**

## Установка и запуск

1. Убедитесь, что установлены все зависимости:
   ```bash
   vagrant plugin install vagrant-vmware-desktop
   ```

2. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/azalio/cilium-l2-announcements-workshop.git
   cd cilium-l2-announcements-workshop
   ```

3. Запустите виртуальные машины:
   ```bash
   vagrant up
   ```

4. После завершения настройки проверьте состояние кластера:
   ```bash
   vagrant ssh server
   kubectl get nodes
   ```

5. Проверьте состояние Cilium:
   ```bash
   kubectl -n kube-system get pods -l k8s-app=cilium
   kubectl -n kube-system get pods -l name=cilium-operator
   ```

## Настройка сети

- **Маршруты между узлами**:
  - На каждом узле настроены статические маршруты для связи между подсетями подов.
  - Маршруты сохраняются в `/etc/network/interfaces.d/90-pod-routes`.

- **Firewall**:
  - На control-plane узле открыты порты для API Server, etcd, Kubelet и других компонентов.
  - На worker-узлах открыты порты для Kubelet и NodePort-сервисов.

## Логирование и отладка

- Логи настройки сохраняются в `/var/log/k8s-setup.log` на каждом узле.
- Для отладки используйте команды:
  ```bash
  journalctl -u containerd
  kubectl describe node <имя-узла>
  ```

## Отладка Cilium

- Проверьте логи Cilium:
  ```bash
  kubectl -n kube-system logs -l k8s-app=cilium
  ```

- Проверьте состояние L2-анонсов:
  ```bash
  kubectl -n kube-system exec -it <cilium-pod-name> -- cilium status
  ```

- Проверьте маршруты между узлами:
  ```bash
  kubectl -n kube-system exec -it <cilium-pod-name> -- cilium bpf tunnel list
  ```

## Авторы

- **Mikhail [azalio] Petrov**
- Версия: 1.0
- Дата: 2025

## Лицензия

Этот проект распространяется под лицензией MIT. Подробности см. в файле [LICENSE](LICENSE).
