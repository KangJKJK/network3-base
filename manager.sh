#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
#

check_env() {
    echo "checking env.." >&2
    # grep -q returns 0 if found, else 1
    if ! dpkg -l | grep -qw iptables; then
        apt-get install iptables -y
    fi

    if ! dpkg -l | grep -qw net-tools; then
        apt-get install net-tools -y
    fi
    ip_forward="$(sysctl net.ipv4.ip_forward)"
    if ! [[ $ip_forward =~ 1 ]]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo -e "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
        sysctl -p
    fi
}

set -e -o pipefail
shopt -s extglob
export LC_ALL=C

ARCH=$(uname -m)
case $ARCH in
    x86_64)
        echo "System architecture is x86_64 (64-bit)"
        ;;
    aarch64|arm64)
        echo "System architecture is ARM64 (64-bit)"
        ARCH="arm64"
        ;;
    *)
        echo "System architecture: $ARCH, not supported"
        exit 1
        ;;
esac
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
export PATH="${SELF%/*}/$ARCH:$PATH"

WG_CONFIG=""
INTERFACE=""
ADDRESSES=( )
MTU=""
DNS=( )
DNS_SEARCH=( )
TABLE=""
WG_NEW_KEY="null"
PRE_UP=( )
POST_UP=( )
PRE_DOWN=( )
POST_DOWN=( )
SAVE_CONFIG=0
CONFIG_FILE=""
PROGRAM="${0##*/}"
ARGS=( "$@" )

cmd() {
    #echo "[#] $*" >&2
    "$@"
}

die() {
    echo "$PROGRAM: $*" >&2
    exit 1
}

parse_options() {
    local interface_section=0 line key value stripped v netiface
    netiface=$(ip -o -4 route show to default | awk '{print $5}')
    echo "local netiface is $netiface" >&2
    CONFIG_FILE="$1"
    #[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] && CONFIG_FILE="/etc/wireguard/$CONFIG_FILE.conf"
    [[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] && CONFIG_FILE="./$CONFIG_FILE.conf"
    [[ -e $CONFIG_FILE ]] || die "\`$CONFIG_FILE' does not exist"
    [[ $CONFIG_FILE =~ (^|/)([a-zA-Z0-9_=+.-]{1,15})\.conf$ ]] || die "The config file must be a valid interface name, followed by .conf"
    CONFIG_FILE="$(readlink -f "$CONFIG_FILE")"
#   ((($(stat -c '0%#a' "$CONFIG_FILE") & $(stat -c '0%#a' "${CONFIG_FILE%/*}") & 0007) == 0)) || echo "Warning: \`$CONFIG_FILE' is world accessible" >&2
    ((($(stat -c '0%#a' "$CONFIG_FILE") & $(stat -c '0%#a' "${CONFIG_FILE%/*}") & 0007) == 0)) || echo "Applying configurations.." >&2
    INTERFACE="${BASH_REMATCH[2]}"
    shopt -s nocasematch
    while read -r line || [[ -n $line ]]; do
        stripped="${line%%\#*}"
        key="${stripped%%=*}"; key="${key##*([[:space:]])}"; key="${key%%*([[:space:]])}"
        value="${stripped#*=}"; value="${value##*([[:space:]])}"; value="${value%%*([[:space:]])}"
        [[ $key == "["* ]] && interface_section=0
        [[ $key == "[Interface]" ]] && interface_section=1
        if [[ $interface_section -eq 1 ]]; then
            case "$key" in
            Address) ADDRESSES+=( ${value//,/ } ); continue ;;
            MTU) MTU="$value"; continue ;;
            DNS) for v in ${value//,/ }; do
                [[ $v =~ (^[0-9.]+$)|(^.*:.*$) ]] && DNS+=( $v ) || DNS_SEARCH+=( $v )
            done; continue ;;
            Table) TABLE="$value"; continue ;;
            PreUp) PRE_UP+=( "$value" ); continue ;;
            PreDown) PRE_DOWN+=( "$value" ); continue ;;
            PostUp) POST_UP+=( "${value//eth0/$netiface}" ); continue ;;
            PostDown) POST_DOWN+=( "${value//eth0/$netiface}" ); continue ;;
            SaveConfig) read_bool SAVE_CONFIG "$value"; continue ;;
            esac
        fi
        WG_CONFIG+="$line"$'\n'
    done < "$CONFIG_FILE"
    shopt -u nocasematch
}

read_bool() {
    case "$2" in
    true) printf -v "$1" 1 ;;
    false) printf -v "$1" 0 ;;
    *) die "\`$2' is neither true nor false"
    esac
}

auto_su() {
    [[ $UID == 0 ]] || exec sudo -p "$PROGRAM must be run as root. Please enter the password for %u to continue: " -- "$BASH" -- "$SELF" "${ARGS[@]}"
}

add_if() {
    local INTERFACE="$1"
    echo "Starting node with interface: $INTERFACE" >&2

    if ! ip link add "$INTERFACE" type wireguard; then
        echo "Failed to add interface $INTERFACE" >&2
        return 1
    fi

    # INTERFACE가 올바르게 생성되었는지 확인
    if ip link show "$INTERFACE" > /dev/null; then
        # WireGuard 설정 적용
        wg set "$INTERFACE" private-key /usr/local/etc/wireguard/utun.key
        ip link set up dev "$INTERFACE"
    else
        echo "Interface $INTERFACE not found" >&2
        return 1
    fi

    echo "Interface $INTERFACE is up." >&2
}

add_addr() {
    local proto=-4
    [[ $1 == *:* ]] && proto=-6
    cmd ip $proto address add "$1" dev "$INTERFACE"
}

set_mtu_up() {
    local mtu=0 endpoint output
    if [[ -n $MTU ]]; then
        cmd ip link set mtu "$MTU" dev "$INTERFACE"
        return
    fi
    while read -r _ endpoint; do
        [[ $endpoint =~ ^\[?([a-z0-9:.]+)\]?:[0-9]+$ ]] || continue
        output="$(ip route get "${BASH_REMATCH[1]}" || true)"
        [[ ( $output =~ mtu\ ([0-9]+) || ( $output =~ dev\ ([^ ]+) && $(ip link show dev "${BASH_REMATCH[1]}") =~ mtu\ ([0-9]+) ) ) && ${BASH_REMATCH[1]} -gt $mtu ]] && mtu="${BASH_REMATCH[1]}"
    done < <(wg show "$INTERFACE" endpoints)
    if [[ $mtu -eq 0 ]]; then
        read -r output < <(ip route show default || true) || true
        [[ ( $output =~ mtu\ ([0-9]+) || ( $output =~ dev\ ([^ ]+) && $(ip link show dev "${BASH_REMATCH[1]}") =~ mtu\ ([0-9]+) ) ) && ${BASH_REMATCH[1]} -gt $mtu ]] && mtu="${BASH_REMATCH[1]}"
    fi
    [[ $mtu -gt 0 ]] || mtu=1500
    cmd ip link set mtu $(( mtu - 80 )) dev "$INTERFACE"
}

add_route() {
    local proto=-4
    [[ $1 == *:* ]] && proto=-6
    [[ $TABLE != off ]] || return 0

    if [[ -n $TABLE && $TABLE != auto ]]; then
        cmd ip $proto route add "$1" dev "$INTERFACE" table "$TABLE"
    elif [[ $1 == */0 ]]; then
        add_default "$1"
    else
        [[ -n $(ip $proto route show dev "$INTERFACE" match "$1" 2>/dev/null) ]] || cmd ip $proto route add "$1" dev "$INTERFACE"
    fi
}

get_fwmark() {
    local fwmark
    fwmark="$(wg show "$INTERFACE" fwmark)" || return 1
    [[ -n $fwmark && $fwmark != off ]] || return 1
    printf -v "$1" "%d" "$fwmark"
    return 0
}

remove_firewall() {
    if type -p nft >/dev/null; then
        local table nftcmd
        while read -r table; do
            [[ $table == *" wg-quick-$INTERFACE" ]] && printf -v nftcmd '%sdelete %s\n' "$nftcmd" "$table"
        done < <(nft list tables 2>/dev/null)
        [[ -z $nftcmd ]] || cmd nft -f <(echo -n "$nftcmd")
    fi
    if type -p iptables >/dev/null; then
        local line iptables found restore
        for iptables in iptables ip6tables; do
            restore="" found=0
            while read -r line; do
                [[ $line == "*"* || $line == COMMIT || $line == "-A "*"-m comment --comment \"wg-quick(8) rule for $INTERFACE\""* ]] || continue
                [[ $line == "-A"* ]] && found=1
                printf -v restore '%s%s\n' "$restore" "${line/#-A/-D}"
            done < <($iptables-save 2>/dev/null)
            [[ $found -ne 1 ]] || echo -n "$restore" | cmd $iptables-restore -n
        done
    fi
}

HAVE_SET_FIREWALL=0
add_default() {
    local table line
    if ! get_fwmark table; then
        table=51820
        while [[ -n $(ip -4 route show table $table 2>/dev/null) || -n $(ip -6 route show table $table 2>/dev/null) ]]; do
            ((table++))
        done
        cmd wg set "$INTERFACE" fwmark $table
    fi
    local proto=-4 iptables=iptables pf=ip
    [[ $1 == *:* ]] && proto=-6 iptables=ip6tables pf=ip6
    cmd ip $proto route add "$1" dev "$INTERFACE" table $table
    cmd ip $proto rule add not fwmark $table table $table
    cmd ip $proto rule add table main suppress_prefixlength 0

    local marker="-m comment --comment \"wg-quick(8) rule for $INTERFACE\"" restore=$'*raw\n' nftable="wg-quick-$INTERFACE" nftcmd
    printf -v nftcmd '%sadd table %s %s\n' "$nftcmd" "$pf" "$nftable"
    printf -v nftcmd '%sadd chain %s %s preraw { type filter hook prerouting priority -300; }\n' "$nftcmd" "$pf" "$nftable"
    printf -v nftcmd '%sadd chain %s %s premangle { type filter hook prerouting priority -150; }\n' "$nftcmd" "$pf" "$nftable"
    printf -v nftcmd '%sadd chain %s %s postmangle { type filter hook postrouting priority -150; }\n' "$nftcmd" "$pf" "$nftable"
    while read -r line; do
        [[ $line =~ .*inet6?\ ([0-9a-f:.]+)/[0-9]+.* ]] || continue
        printf -v restore '%s-I PREROUTING ! -i %s -d %s -m addrtype ! --src-type LOCAL -j DROP %s\n' "$restore" "$INTERFACE" "${BASH_REMATCH[1]}" "$marker"
        printf -v nftcmd '%sadd rule %s %s preraw iifname != "%s" %s daddr %s fib saddr type != local drop\n' "$nftcmd" "$pf" "$nftable" "$INTERFACE" "$pf" "${BASH_REMATCH[1]}"
    done < <(ip -o $proto addr show dev "$INTERFACE" 2>/dev/null)
    printf -v restore '%sCOMMIT\n*mangle\n-I POSTROUTING -m mark --mark %d -p udp -j CONNMARK --save-mark %s\n-I PREROUTING -p udp -j CONNMARK --restore-mark %s\nCOMMIT\n' "$restore" $table "$marker" "$marker"
    printf -v nftcmd '%sadd rule %s %s postmangle meta l4proto udp mark %d ct mark set mark \n' "$nftcmd" "$pf" "$nftable" $table
    printf -v nftcmd '%sadd rule %s %s premangle meta l4proto udp meta mark set ct mark \n' "$nftcmd" "$pf" "$nftable"
    [[ $proto == -4 ]] && cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1
    if type -p nft >/dev/null; then
        cmd nft -f <(echo -n "$nftcmd")
    else
        echo -n "$restore" | cmd $iptables-restore -n
    fi
    HAVE_SET_FIREWALL=1
    return 0
}

set_config() {
    [[ -d "/usr/local/etc/wireguard" ]] || (cmd mkdir -p /usr/local/etc/wireguard)
    if [[ ! -f "/usr/local/etc/wireguard/utun.key" ]]; then
        cmd wg genkey > /usr/local/etc/wireguard/utun.key
        cmd chmod 600 /usr/local/etc/wireguard/utun.key
    fi
    WG_NEW_KEY="$(cat /usr/local/etc/wireguard/utun.key)"
    echo "after setting wg key." >&2
    cmd wg setconf "$INTERFACE" <(echo "$WG_CONFIG" | sed "s#_PrivateKey_#$WG_NEW_KEY#")
}

cmd_key() {
    if [[ -f "/usr/local/etc/wireguard/utun.key" ]]; then
        cat /usr/local/etc/wireguard/utun.key
    else
        echo "utun.key 파일을 찾을 수 없습니다."
    fi
}

save_config() {
    local old_umask new_config current_config address cmd
    [[ $(ip -all -brief address show dev "$INTERFACE") =~ ^$INTERFACE\ +\ [A-Z]+\ +(.+)$ ]] || true
    new_config=$'[Interface]\n'
    for address in ${BASH_REMATCH[1]}; do
        new_config+="Address = $address"$'\n'
    done
    [[ -n $MTU && $(ip link show dev "$INTERFACE") =~ mtu\ ([0-9]+) ]] && new_config+="MTU = ${BASH_REMATCH[1]}"$'\n'
    [[ -n $TABLE ]] && new_config+="Table = $TABLE"$'\n'
    [[ $SAVE_CONFIG -eq 0 ]] || new_config+=$'SaveConfig = true\n'
    for cmd in "${PRE_UP[@]}"; do
        new_config+="PreUp = $cmd"$'\n'
    done
    for cmd in "${POST_UP[@]}"; do
        new_config+="PostUp = $cmd"$'\n'
    done
    for cmd in "${PRE_DOWN[@]}"; do
        new_config+="PreDown = $cmd"$'\n'
    done
    for cmd in "${POST_DOWN[@]}"; do
        new_config+="PostDown = $cmd"$'\n'
    done
    old_umask="$(umask)"
    umask 077
    current_config="$(cmd wg showconf "$INTERFACE")"
    trap 'rm -f "$CONFIG_FILE.tmp"; exit' INT TERM EXIT
    echo "${current_config/\[Interface\]$'\n'/$new_config}" > "$CONFIG_FILE.tmp" || die "Could not write configuration file"
    sync "$CONFIG_FILE.tmp"
    mv "$CONFIG_FILE.tmp" "$CONFIG_FILE" || die "Could not move configuration file"
    trap - INT TERM EXIT
    umask "$old_umask"
}

execute_hooks() {
    local hook
    for hook in "$@"; do
        hook="${hook//%i/$INTERFACE}"
        (eval "$hook")
    done
}

cmd_usage() {
    cat >&2 <<-_EOF
    Usage: $PROGRAM [ up | down ]
    sudo is necessary for this program would add / remove virtual network interface.
_EOF
}

cmd_up() {
    # 고유한 인터페이스 이름 생성
    local NEW_INTERFACE
    local PROXY_HASH=$(echo -n "$http_proxy" | md5sum | cut -d' ' -f1)  # 프록시의 해시값 사용
    while true; do
        NEW_INTERFACE="wg${PROXY_HASH:0:6}$((RANDOM % 1000))"  # 해시값과 랜덤 숫자 조합
        if ! ip link show "$NEW_INTERFACE" > /dev/null 2>&1; then
            break
        fi
    done
    echo "Starting new interface: $NEW_INTERFACE" >&2

    INTERFACE="$NEW_INTERFACE"

    # WireGuard 설정 파일 생성
    cat <<EOF > /etc/wireguard/$INTERFACE.conf
[Interface]
Address = 10.0.0.1/24
ListenPort = $CURRENT_PORT
PrivateKey = $(cat /usr/local/etc/wireguard/utun.key)

[Peer]
PublicKey = <peer_public_key>
AllowedIPs = 10.0.0.2/32
EOF

    add_if "$INTERFACE"  # NEW_INTERFACE를 인자로 전달
    echo "after adding if." >&2
    set_config
    echo "after setting config." >&2
    for i in "${ADDRESSES[@]}"; do
        add_addr "$i"
    done
    echo "after adding addr." >&2
    set_mtu_up
    echo "after mtu up." >&2
    add_route "10.77.64.0/20"
    echo "routes added." >&2
    execute_hooks "${POST_UP[@]}"
    echo "node is ready." >&2
    echo "Access the dashboard by opening https://account.network3.ai/main?o=<your_ip>:8080 in chrome where <your_ip> is the accessible ip of this machine" >&2
    trap - INT TERM EXIT

    # WireGuard를 포그라운드에서 실행하여 컨테이너가 종료되지 않도록 함
    exec wg-quick up "$INTERFACE"
}

cmd_down() {
    echo "stopping the node.." >&2
    [[ " $(wg show interfaces) " == *" $INTERFACE "* ]] || die "\`$INTERFACE' is not a WireGuard interface"
    execute_hooks "${PRE_DOWN[@]}"
    [[ $SAVE_CONFIG -eq 0 ]] || save_config
    del_if
    remove_firewall || true
    execute_hooks "${POST_DOWN[@]}"
    echo "node is closed." >&2
}

cmd_save() {
    [[ " $(wg show interfaces) " == *" $INTERFACE "* ]] || die "\`$INTERFACE' is not a WireGuard interface"
    save_config
}

cmd_strip() {
    echo "$WG_CONFIG"
}

# ~~ function override insertion point ~~

if [[ $# -eq 1 && ( $1 == --help || $1 == -h || $1 == help ) ]]; then
    cmd_usage
elif [[ $# -eq 1 && $1 == up ]]; then
    auto_su
    check_env
    cmd_up
elif [[ $# -eq 1 && $1 == down ]]; then
    auto_su
    parse_options "$INTERFACE"
    cmd_down
elif [[ $# -eq 1 && $1 == key ]]; then
    auto_su
    cmd_key
else
    cmd_usage
    exit 1
fi

exit 0
   
