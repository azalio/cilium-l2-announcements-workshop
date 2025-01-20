# L2 анонсы в cilium

 # Оглавление

 1. [Введение](#введение)
 2. [Настройка окружения](#настройка-окружения)
 3. [Деплой Nginx](#деплой-nginx)
 4. [Настройка Ingress](#настройка-ingress)
 5. [Настройка LoadBalancer IP Pool](#настройка-loadbalancer-ip-pool)
 6. [Проблема с ARP](#проблема-с-arp)
 7. [Включение L2 анонсов](#включение-l2-анонсов)
 8. [Как это работает](#как-это-работает)
    - [Настройка L2 Policy](#настройка-l2-policy)
    - [Lease захват](#lease-захват)
    - [BPF Map для ARP](#bpf-map-для-arp)
    - [Преобразование IP](#преобразование-ip)
 9. [Путь пакета](#путь-пакета)
 10. [Вопросы и ответы](#вопросы-и-ответы)
 11. [Дополнительные материалы](#дополнительные-материалы)

## Введение <a name="введение"></a>
В процессе работы по описыванию [опций цилиум-агента](https://docs.cilium.io/en/stable/cmdref/cilium-agent/) я наткнулся на опцию, которая мне была не ясна:
```
--agent-liveness-update-interval duration                   Interval at which the agent updates liveness time for the datapath (default 1s)
```
А точнее мне было не понятно для чего эта опция нужна и на что она влияет.  
В итоге получилась следующая статья.

## Настройка окружения <a name="настройка-окружения"></a>
Для начала надо настроить окружение, воспользуйтесь [README.md](../README.md)

<details>
  <summary>Немного о сетапе самого k8s && cilium</summary>
У нас следующий расклад

**jumpbox** - клиент не входящий в кластер kubernetes, но у него добавлен роут для LB
```bash


ip ro add 10.0.10.0/24 dev eth1 scope link || true # Добавили сеть для LB на хост чтобы он слал ARP запросы в сеть.
```

**server** - control plane  
```bash
root@server:/home/vagrant# ip addr sh
# ... тут был lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:0c:29:34:87:04 brd ff:ff:ff:ff:ff:ff
    altname enp2s0
    altname ens160
    inet 172.16.65.134/24 brd 172.16.65.255 scope global dynamic eth0
       valid_lft 1393sec preferred_lft 1393sec
    inet6 fe80::20c:29ff:fe34:8704/64 scope link
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:34:87:0e brd ff:ff:ff:ff:ff:ff
    altname enp18s0
    altname ens224
    inet 192.168.56.20/24 brd 192.168.56.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe34:870e/64 scope link
       valid_lft forever preferred_lft forever
4: cilium_net@cilium_host: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 5a:52:88:29:22:6d brd ff:ff:ff:ff:ff:ff
    inet6 fe80::5852:88ff:fe29:226d/64 scope link
       valid_lft forever preferred_lft forever
5: cilium_host@cilium_net: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether b6:78:3c:93:b8:45 brd ff:ff:ff:ff:ff:ff
    inet 10.200.0.7/32 scope global cilium_host
       valid_lft forever preferred_lft forever
    inet6 fe80::b478:3cff:fe93:b845/64 scope link
       valid_lft forever preferred_lft forever
7: lxc_health@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 9a:dd:c2:3b:95:10 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::98dd:c2ff:fe3b:9510/64 scope link
       valid_lft forever preferred_lft forever
9: lxcad113d8e8e91@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether ba:3b:e2:45:f7:6e brd ff:ff:ff:ff:ff:ff link-netns cni-5c70ca6a-fc04-03a7-566f-6f64ae28bac2
    inet6 fe80::b83b:e2ff:fe45:f76e/64 scope link
       valid_lft forever preferred_lft forever
11: lxcf9c6a3bae21b@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 5e:d5:84:bb:4e:79 brd ff:ff:ff:ff:ff:ff link-netns cni-c1fbcc80-4c2c-8f05-9d82-c7191c850da7
    inet6 fe80::5cd5:84ff:febb:4e79/64 scope link
       valid_lft forever preferred_lft forever

root@server:/home/vagrant# ip ro sh
default via 172.16.65.2 dev eth0
10.200.0.52 dev lxcad113d8e8e91 proto kernel scope link
10.200.0.141 dev lxcf9c6a3bae21b proto kernel scope link
10.200.0.142 dev lxc_health proto kernel scope link
10.200.1.0/24 via 192.168.56.50 dev eth1 # роут для подовых сетей
10.200.2.0/24 via 192.168.56.60 dev eth1 # роут для подовых сетей
172.16.65.0/24 dev eth0 proto kernel scope link src 172.16.65.134
192.168.56.0/24 dev eth1 proto kernel scope link src 192.168.56.20       
```

**node-0** - нода k8s  
**node-1** - нода k8s  

Cilium с нативным роутингом. Туннели не используются. Версия v1.16.5.

```bash
helm upgrade --install cilium cilium/cilium --version 1.16.5 --namespace kube-system \
  --set l2announcements.enabled=true \
  --set externalIPs.enabled=true \
  --set kubeProxyReplacement=true \
  --set ipam.mode=kubernetes \
  --set k8sServiceHost=192.168.56.20 \
  --set k8sServicePort=6443 \
  --set operator.replicas=1 \
  --set routingMode=native \
  --set ipv4NativeRoutingCIDR=10.200.0.0/22 \
  --set endpointRoutes.enabled=true \
  --set ingressController.enabled=true \
  --set ingressController.loadbalancerMode=dedicated 
```
Ядро
```bash
# uname -a
Linux node-1 6.1.0-20-arm64 #1 SMP Debian 6.1.85-1 (2024-04-11) aarch64 aarch64 aarch64 GNU/Linux
```
</details>

## Деплой Nginx <a name="деплой-nginx"></a>
В этом разделе мы развернем простой веб-сервер на основе Nginx.

### Шаг 1. Создание Deployment
```bash
# vagrant ssh server
# sudo bash

# kubectl apply -f workshop/nginx-deployment.yaml
deployment.apps/nginx created

# kubectl apply -f workshop/nginx-service.yaml
service/nginx created
```
### Шаг 3. Проверка работы
Убедимся что сервис работает
```bash
# kubectl get pod -o wide
NAME                   READY   STATUS    RESTARTS   AGE   IP             NODE     NOMINATED NODE   READINESS GATES
nginx-96b9d695-25swg   1/1     Running   0          55s   10.200.2.189   node-1   <none>           <none>

# kubectl get svc nginx
NAME    TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)   AGE
nginx   ClusterIP   10.96.79.80   <none>        80/TCP    89s

# curl 10.96.79.80
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...

# curl 10.200.2.189
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```
[↑ К оглавлению](#оглавление) | [← Назад](#предыдущий-раздел) | [Далее →](#следующий-раздел)

Применяем манифест `ingress`

```bash
# kubectl apply -f workshop/basic-ingress.yaml

# kubectl get ingress
NAME            CLASS    HOSTS   ADDRESS   PORTS   AGE
basic-ingress   cilium   *                 80      40s
```

Так же будет создан сервис для этого `ingress`
```bash
# kubectl get svc cilium-ingress-basic-ingress
NAME                           TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
cilium-ingress-basic-ingress   LoadBalancer   10.96.156.194   <pending>     80:31017/TCP,443:32600/TCP   115s
```

Как вы видите в поле `EXTERNAL-IP` статус <pending> потому что ему пока неоткуда взяться.


## CiliumLoadBalancerIPPool
https://docs.cilium.io/en/stable/network/lb-ipam/

Создадим `CiliumLoadBalancerIPPool`
```bash
kubectl apply -f workshop/lb.yaml
```

И у нас сразу появится IP у EXTERNAL-IP
```bash
# kubectl get svc cilium-ingress-basic-ingress
NAME                           TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
cilium-ingress-basic-ingress   LoadBalancer   10.96.156.194   10.0.10.0     80:31017/TCP,443:32600/TCP   4m9s
```

И он сразу работает 
```bash
# curl 10.0.10.0
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```

Зайдем в другой консоли на наш клиент `jumpbox` и убедимся что сайт открывается.
```bash
# vagrant ssh jumpbox
root@jumpbox:/home/vagrant# curl 10.0.10.0
curl: (7) Failed to connect to 10.0.10.0 port 80 after 3074 ms: Couldn't connect to server
```

Почему так?

Вы, конечно, догадались: на ARP запрос никто не отвечает.

```bash
root@server:/home/vagrant# tcpdump -n -i any arp host 10.0.10.0
tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes

21:15:05.927064 eth1  B   ARP, Request who-has 10.0.10.0 tell 192.168.56.10, length 46
21:15:06.948513 eth1  B   ARP, Request who-has 10.0.10.0 tell 192.168.56.10, length 46
21:15:07.973210 eth1  B   ARP, Request who-has 10.0.10.0 tell 192.168.56.10, length 46
21:15:08.998950 eth1  B   ARP, Request who-has 10.0.10.0 tell 192.168.56.10, length 46
21:15:10.024080 eth1  B   ARP, Request who-has 10.0.10.0 tell 192.168.56.10, length 46
21:15:11.050053 eth1  B   ARP, Request who-has 10.0.10.0 tell 192.168.56.10, length 46

root@jumpbox:/home/vagrant# arp -n 10.0.10.0
Address                  HWtype  HWaddress           Flags Mask            Iface
10.0.10.0                        (incomplete)                              eth1
```

Давайте включим ARP анонсы.

```bash
root@server:/home/vagrant# tcpdump -n -i any arp host 10.0.10.0 & # запустили tcpdump в бекграунде, чтобы сразу увидеть что происходит.
[1] 17207

root@server:/home/vagrant# kubectl apply -f workshop/l2.yaml
ciliuml2announcementpolicy.cilium.io/policy1 created

21:18:52.093372 eth1  B   ARP, Reply 10.0.10.0 is-at 00:0c:29:0d:b7:76, length 46
21:18:52.102795 eth0  B   ARP, Reply 10.0.10.0 is-at 00:0c:29:0d:b7:6c, length 46

root@jumpbox:/home/vagrant# tcpdump -n -i any arp
tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes

21:18:52.113122 eth1  B   ARP, Reply 10.0.10.0 is-at 00:0c:29:0d:b7:76, length 46
21:18:52.113211 eth1  B   ARP, Reply 10.0.10.1 is-at 00:0c:29:e3:b1:b2, length 46
21:18:52.122245 eth0  B   ARP, Reply 10.0.10.1 is-at 00:0c:29:e3:b1:a8, length 46
21:18:52.122495 eth0  B   ARP, Reply 10.0.10.0 is-at 00:0c:29:0d:b7:6c, length 46

root@jumpbox:/home/vagrant# arp -n 10.0.10.0
Address                  HWtype  HWaddress           Flags Mask            Iface
10.0.10.0                ether   00:0c:29:0d:b7:76   C                     eth1
```

Заметьте, сразу после включения на сервера прилетел **ответ** от ARP хотя мы ничего не запрашивали.  
Это [Gratuitous ARP](https://wiki.wireshark.org/Gratuitous_ARP) - механизм, при котором при появлении нового адреса сервер оповещает своих соседей по L2 домену о новом маке.

Итак, у нас есть mac `00:0c:29:0d:b7:76`. 
Это мак-адрес интерфейса eth1 ноды **node-1**

```bash
root@node-1:/home/vagrant# ip addr sh | grep -1 00:0c:29:0d:b7:76
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:0d:b7:76 brd ff:ff:ff:ff:ff:ff
    altname enp18s0
```

Так же легко это выяснить поискав какая нода захватила лизу

```bash
# kubectl get lease -n kube-system cilium-l2announce-default-cilium-ingress-basic-ingress
NAME                                                     HOLDER   AGE
cilium-l2announce-default-cilium-ingress-basic-ingress   node-1   8m49s
```

Но как это все работает?

Основную информацию вы, конечно, можете прочитать в [документации](https://docs.cilium.io/en/latest/network/l2-announcements/), я же расскажу чуть-чуть побольше.

<details>
  <summary>1. Настраиваем policy включающие l2 анонсы</summary>

```yaml
apiVersion: "cilium.io/v2alpha1"
kind: CiliumL2AnnouncementPolicy
metadata:
  name: policy1
spec:
  nodeSelector:
    matchExpressions:
      - key: node-role.kubernetes.io/control-plane
        operator: DoesNotExist
  interfaces:
  - ^eth[0-9]+
  externalIPs: true
  loadBalancerIPs: true
```
</details>

<details>
<summary> 2. Цилиум захватывает лизу </summary>

```bash
root@server:/home/vagrant# kubectl get lease -n kube-system | grep l2announce
cilium-l2announce-default-cilium-ingress-basic-ingress   node-1                                                                      16m
cilium-l2announce-kube-system-cilium-ingress             node-0                                                                      16m
```
</details>

<details>
<summary> 3. На ноде создается bpf map, отвечающая за ARP ответы по анонсируемому IP</summary>

```bash
# kubectl get svc cilium-ingress-basic-ingress
NAME                           TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
cilium-ingress-basic-ingress   LoadBalancer   10.96.156.194   10.0.10.0     80:31017/TCP,443:32600/TCP   24h
```

```bash
root@node-1:/home/cilium# bpftool map show pinned /sys/fs/bpf/tc/globals/cilium_l2_responder_v4
72: hash  name cilium_l2_respo  flags 0x1
	key 8B  value 8B  max_entries 4096  memlock 65536B
	btf_id 125
root@node-1:/home/cilium# bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_l2_responder_v4
[{
        "key": {
            "ip4": 655370, # IP
            "ifindex": 2   # Номер интерфейса в системе.
        },
        "value": {
            "responses_sent": 0
        }
    },{
        "key": {
            "ip4": 655370,
            "ifindex": 3
        },
        "value": {
            "responses_sent": 3 # сколько ответов было послано на ARP запрос.
        }
    }
]
```
pinned - закреплена в файловой системе и сохраняется между рестартами.

```bash
root@node-1:/home/cilium# ip link show | grep eth
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    // ...
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
```

Что за число `655370`?

```python
import socket
import struct

# Число в little-endian
number = 655370

# Преобразуем число в IP-адрес
# < — указывает на little-endian.
# I — беззнаковое 32-битное целое число.
ip = socket.inet_ntoa(struct.pack('<I', number))
print(ip)
```
`10.0.10.0` - искомый IP адрес LB.
</details>

Итого - сетевой путь пакета выглядит так (если считаем что в кеше нет нужного мака):

```scheme
 +----------+        Broadcast ARP       +-----------+
 | jumpbox  | -- "Who has 10.0.10.0?" -->| L2 domain |
 +----+-----+                           +-----+-----+
      |                                       |
      |                                       |
      |                    ARP Reply          |
      v                                       v
   (node-1)   <-- "10.0.10.0 is-at 00:0c:29:0d:b7:76"
```

`jumpbox` - посылает широковещательный запрос с вопросом кто отвечает за 10.0.10.0.
`все сервера l2 домена` - получают этот запрос.
`node-1` - отвечает на этот запрос с мак адресом интерфейса, который принял ARP запрос.

А как node-1 **ответила** на `arp` запрос?

Предположим что запрос пришел на `eth1`.

На этом интерфейсе подцеплены bpf программы (у нас же цилиум, елки-палки!).
```bash
tc filter show dev eth1 ingress
filter protocol all pref 1 bpf chain 0
filter protocol all pref 1 bpf chain 0 handle 0x1 cil_from_netdev-eth1 direct-action not_in_hw id 3640 tag e1f4a3d35ae9c0f0 jited
```

И входящий трафик обрабатывает программа `cil_from_netdev-eth1`.
Чуть больше информации можно посмотреть так
```bash
root@node-1:/home/cilium# bpftool prog show id 3640
3640: sched_cls  name cil_from_netdev  tag e1f4a3d35ae9c0f0  gpl
	loaded_at 2025-01-19T18:24:42+0000  uid 0
	xlated 3856B  jited 3192B  memlock 4096B  map_ids 55,548,17,72,54
	btf_id 3385
```

`direct-action` - bpf программа сама примет решение о том что делать с принятым пакетом.

В цилиуме эта bpf программа аттачится к интерфейсу [тут](https://github.com/cilium/cilium/blob/v1.16.5/pkg/datapath/loader/loader.go#L321)
```go
// reloadHostDatapath (re)attaches programs from bpf_host.c to:
// - cilium_host: cil_to_host ingress and cil_from_host to egress
// - cilium_net: cil_to_host to ingress
// - native devices: cil_from_netdev to ingress and (optionally) cil_to_netdev to egress if certain features require it
func (l *loader) reloadHostDatapath(ep datapath.Endpoint, spec *ebpf.CollectionSpec, devices []string) error {
	// Replace programs on cilium_host.
    // ...
                // Attach cil_from_netdev to ingress.
                if err := attachSKBProgram(iface, coll.Programs[symbolFromHostNetdevEp], symbolFromHostNetdevEp,
                        linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
                        return fmt.Errorf("interface %s ingress: %w", device, err)
                }
```

Саму программу `cil_from_netdev` можно найти [тут](https://github.com/cilium/cilium/blob/v1.16.5/bpf/bpf_host.c#L1287)
```c
/*
 * from-netdev is attached as a tc ingress filter to one or more physical devices
 * managed by Cilium (e.g., eth0). This program is only attached when:
 * - the host firewall is enabled, or
 * - BPF NodePort is enabled, or
 * - L2 announcements are enabled, or
 * - WireGuard's host-to-host encryption and BPF NodePort are enabled
 */
__section_entry
int cil_from_netdev(struct __ctx_buff *ctx)
// ...
return handle_netdev(ctx, false);
```

Запрос передается в [`handle_netdev`](https://github.com/cilium/cilium/blob/v1.16.5/bpf/bpf_host.c#L1244) и уходит в `do_netdev`.
```c
/**
 * handle_netdev
 * @ctx		The packet context for this program
 * @from_host	True if the packet is from the local host
 *
 * Handle netdev traffic coming towards the Cilium-managed network.
 */
static __always_inline int
handle_netdev(struct __ctx_buff *ctx, const bool from_host)

// ...

return do_netdev(ctx, proto, from_host);
```

[`do_netdev`](https://github.com/cilium/cilium/blob/v1.16.5/bpf/bpf_host.c#L1074) обрабатывает `ARP`
```c
do_netdev(struct __ctx_buff *ctx, __u16 proto, const bool from_host)
// ...
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER || \
     defined ENABLE_L2_ANNOUNCEMENTS
	case bpf_htons(ETH_P_ARP):
		#ifdef ENABLE_L2_ANNOUNCEMENTS
			ret = handle_l2_announcement(ctx);
		#else
			ret = CTX_ACT_OK;
		#endif
		break;
# endif
// ...
```

Заметьте, если анонсы не включены - то пакет просто пропустится `CTX_ACT_OK` и не будет обработан, иначе будет вызвана функция `handle_l2_announcement`.

[`handle_l2_announcement`](https://github.com/cilium/cilium/blob/v1.16.5/bpf/bpf_host.c#L1032)
```c
#ifdef ENABLE_L2_ANNOUNCEMENTS
static __always_inline int handle_l2_announcement(struct __ctx_buff *ctx)
// ...
```

В которой будет:
1. Проверено что <s>брат</s> цилиум-агент жив (опция `agent-liveness-update-interval`)
```c
// ...
	__u32 index = RUNTIME_CONFIG_AGENT_LIVENESS;
	__u64 *time;

	time = map_lookup_elem(&CONFIG_MAP, &index);
	if (!time)
		return CTX_ACT_OK;

	/* If the agent is not active for X seconds, we can't trust the contents
	 * of the responder map anymore. So stop responding, assuming other nodes
	 * will take over for a node without an active agent.
	 */
	if (ktime_get_ns() - (*time) > L2_ANNOUNCEMENTS_MAX_LIVENESS)
		return CTX_ACT_OK;
// ...
```

Как вы думаете где хранится значение `time`?
Конечно! В еще одной bpf мапе!

```bash
root@node-1:/home/cilium# cilium-dbg map get cilium_runtime_config | head -3
Key             Value              State   Error
UTimeOffset     3393110285156250
AgentLiveness   53302401940736 # monolithic time https://docs.redhat.com/en/documentation/red_hat_enterprise_linux_for_real_time/7/html/reference_guide/sect-posix_clocks
```

2. Что пакет реально ARP пакет
```c
	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
		return CTX_ACT_OK;
```

3. Проверено что мы вообще должны отвечать на этот `arp` (помните про лизу?)
```c
	key.ip4 = tip;
	key.ifindex = ctx->ingress_ifindex;
	stats = map_lookup_elem(&L2_RESPONDER_MAP4, &key);
	if (!stats)
		return CTX_ACT_OK;
```
Вот эта мапка
```bash
root@node-1:/home/cilium# bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_l2_responder_v4
[{
        "key": {
            "ip4": 655370,
            "ifindex": 2
        },
        "value": {
            "responses_sent": 0
        }
    },{
        "key": {
            "ip4": 655370,
            "ifindex": 3
        },
        "value": {
            "responses_sent": 0
        }
    }
]
```

4. Вызовется `arp_respond`
```c
ret = arp_respond(ctx, &mac, tip, &smac, sip, 0);
```

[`arp_respond`](https://github.com/cilium/cilium/blob/main/bpf/lib/arp.h#L75) вызовет `arp_prepare_response` и отправит `ctx_redirect` пакет на интерфейс.
```c
static __always_inline int
arp_respond(struct __ctx_buff *ctx, union macaddr *smac, __be32 sip,
	    union macaddr *dmac, __be32 tip, int direction)
{
	int ret = arp_prepare_response(ctx, smac, sip, dmac, tip);

	if (unlikely(ret != 0)) // ну типа ошибка маловероятна
		goto error;

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY,
			   ctx_get_ifindex(ctx));
	return ctx_redirect(ctx, ctx_get_ifindex(ctx), direction);

error:
	return send_drop_notify_error(ctx, UNKNOWN_ID, ret, CTX_ACT_DROP, METRIC_EGRESS);
}
```

[`ctx_redirect`](https://github.com/cilium/cilium/blob/main/bpf/include/bpf/ctx/skb.h#L89) в итоге вызовет функцию `bpf_redirect` о которой хорошо написано [тут](http://arthurchiao.art/blog/differentiate-bpf-redirects/)

Заметили `direction` = 0?
Это определяет направление пакета (ingress или egress). В коментариях к функции bpf_redirect есть пояснение

>Except for XDP, both ingress and egress interfaces can be used
>for redirection. The **BPF_F_INGRESS** value in *flags* is used
>to make the distinction (ingress path is selected if the flag
>is present, egress path otherwise).

Значение **BPF_F_INGRESS** можно подсмотреть тут:
```bash
root@node-1:/home/cilium# grep -Rw BPF_F_INGRESS /var/lib/cilium/bpf/include/linux/bpf.h
# ..
BPF_F_INGRESS			= (1ULL << 0),
```
Что по сути является числом **1**, а у нас **0**, то есть мы отправили пакет на egress (на выход с eth1).

Итого, путь пакета на node-1
```scheme
 +-------------------+
 |   Внешний хост    |
 |    (jumpbox)      |
 +--------+----------+
          | ARP запрос "Who has 10.0.10.0?"
          v
 +-------------------+
 |   Интерфейс eth1  |
 |     node-1        |
 +--------+----------+
          | Пакет попадает в TC ingress
          v
 +-------------------+
 |  BPF программа    |
 | cil_from_netdev   |
 +--------+----------+
          | Обработка в handle_netdev
          v
 +-------------------+
 |  do_netdev()      |
 +--------+----------+
          | Проверка типа пакета (ARP)
          v
 +-------------------+
 | handle_l2_announcement() |
 +--------+----------+
          | Проверки:
          | 1. Жив ли Cilium агент
          | 2. Это ARP пакет
          | 3. Есть ли запись в L2_RESPONDER_MAP4
          v
 +-------------------+
 | arp_respond()     |
 +--------+----------+
          | Подготовка ARP ответа
          v
 +-------------------+
 | ctx_redirect()    |
 +--------+----------+
          | Перенаправление на egress (direction=0)
          v
 +-------------------+
 |   Интерфейс eth1  |
 |     node-1        |
 +--------+----------+
          | ARP ответ "10.0.10.0 is-at 00:0c:29:0d:b7:76"
          v
 +-------------------+
 |   Внешний хост    |
 |    (jumpbox)      |
 +-------------------+
 ```

Вопрос на засыпку: а что будет если я отключу l2 анонсы, но включу proxy_arp?
// TODO ^

Для тех кто добрался. 
Различия кешированных и не кешированных мап в cilium.
// TODO
