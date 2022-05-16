#!/bin/bash -xe

LINK="enp0s31f6"
BR="vibr0"

nmcli connection add type bridge con-name "${BR}" ifname "${BR}"

nmcli connection add type ethernet slave-type bridge \
    con-name "${BR}-${LINK}" ifname "${LINK}" master "${BR}"

nmcli connection modify "${BR}" ipv4.addresses '192.168.0.25/24'
nmcli connection modify "${BR}" ipv4.gateway '192.168.0.1'
nmcli connection modify "${BR}" ipv4.dns '89.101.251.230 89.101.251.231'
nmcli connection modify "${BR}" ipv4.dns-search 'local'
nmcli connection modify "${BR}" ipv4.method manual
nmcli connection modify "${BR}" connection.autoconnect-slaves 1

nmcli connection down "Wired connection 1"
nmcli connection up "${BR}"
