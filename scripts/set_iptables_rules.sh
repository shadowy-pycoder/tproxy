#!/usr/bin/env bash

# Copyright (C) 2025 shadowy-pycoder
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# rules are taken from https://github.com/shadowy-pycoder/go-http-proxy-to-socks
set -ex

PORT=${1:-8888}
IFACE=${2:-$(ip -4 route get 8.8.8.8 | awk '{print $5}' | tr -d '\n')}

iptables -t mangle -F DIVERT 2>/dev/null || true
iptables -t mangle -X DIVERT 2>/dev/null || true

ip rule del fwmark 1 lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true

ip rule add fwmark 1 lookup 100 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

iptables -t mangle -N DIVERT 2>/dev/null || true
iptables -t mangle -F DIVERT 2>/dev/null || true
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
sysctl -w net.ipv4.ip_forward=1
iptables -t filter -F CTPROXY_APP 2>/dev/null || true
iptables -t filter -D FORWARD -j CTPROXY_APP 2>/dev/null || true
iptables -t filter -X CTPROXY_APP 2>/dev/null || true
iptables -t filter -N CTPROXY_APP 2>/dev/null
iptables -t filter -F CTPROXY_APP
iptables -t filter -A FORWARD -j CTPROXY_APP
iptables -t filter -A CTPROXY_APP -i "$IFACE" -j ACCEPT
iptables -t filter -A CTPROXY_APP -o "$IFACE" -j ACCEPT
iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
iptables -t mangle -D PREROUTING -p tcp -j CTPROXY_APP 2>/dev/null || true
iptables -t mangle -F CTPROXY_APP 2>/dev/null || true
iptables -t mangle -X CTPROXY_APP 2>/dev/null || true
iptables -t mangle -N CTPROXY_APP 2>/dev/null || true
iptables -t mangle -F CTPROXY_APP

iptables -t mangle -A CTPROXY_APP -p tcp -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A CTPROXY_APP -p tcp -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A CTPROXY_APP -p tcp -d 255.255.255.255/32 -j RETURN
if command -v docker >/dev/null 2>&1; then
    for subnet in $(docker network inspect $(docker network ls -q) --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'); do
        iptables -t mangle -A CTPROXY_APP -p tcp -d "$subnet" -j RETURN
        iptables -t mangle -A CTPROXY_APP -p tcp -s "$subnet" -j RETURN
    done
fi
iptables -t mangle -A CTPROXY_APP -p tcp -m mark --mark 100 -j RETURN
iptables -t mangle -A CTPROXY_APP -p tcp -j TPROXY --on-port "$PORT" --tproxy-mark 1
iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
iptables -t mangle -A PREROUTING -p tcp -j CTPROXY_APP
