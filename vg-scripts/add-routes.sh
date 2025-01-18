#!/bin/sh

# Add pod network routes when eth1 interface comes up
if [ "$IFACE" = "eth1" ]; then
    case "$(hostname)" in
        "server")
            ip route add 10.200.1.0/24 via 192.168.56.50 || true
            ip route add 10.200.2.0/24 via 192.168.56.60 || true
            ;;
        "node-0")
            ip route add 10.200.0.0/24 via 192.168.56.20 || true
            ip route add 10.200.2.0/24 via 192.168.56.60 || true
            ;;
        "node-1")
            ip route add 10.200.0.0/24 via 192.168.56.20 || true
            ip route add 10.200.1.0/24 via 192.168.56.50 || true
            ;;
        "jumpbox")
            ip route add 10.200.0.0/24 via 192.168.56.20 || true
            ip route add 10.200.1.0/24 via 192.168.56.50 || true
            ip route add 10.200.2.0/24 via 192.168.56.60 || true
            ;;
    esac
fi
