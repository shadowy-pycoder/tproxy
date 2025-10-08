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

iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
iptables -t mangle -D PREROUTING -p tcp -j CTPROXY_APP 2>/dev/null || true
iptables -t mangle -F CTPROXY_APP 2>/dev/null || true
iptables -t mangle -X CTPROXY_APP 2>/dev/null || true
iptables -t filter -F CTPROXY_APP 2>/dev/null || true
iptables -t filter -D FORWARD -j CTPROXY_APP 2>/dev/null || true
iptables -t filter -X CTPROXY_APP 2>/dev/null || true
iptables -t mangle -F DIVERT 2>/dev/null || true
iptables -t mangle -X DIVERT 2>/dev/null || true

ip rule del fwmark 1 lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
