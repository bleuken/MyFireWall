#!/bin/bash

IPT="/sbin/iptables"
SPAMLIST="blockedip"
SPAMDROPMSG="BLOCKED IP DROP"
SYSCTL="/sbin/sysctl"
BLOCKEDIPS="/root/scripts/blocked.ips.txt"

# Stop certain attacks
echo "Setting sysctl IPv4 settings..."
$SYSCTL net.ipv4.ip_forward=0
$SYSCTL net.ipv4.conf.all.send_redirects=0
$SYSCTL net.ipv4.conf.default.send_redirects=0
$SYSCTL net.ipv4.conf.all.accept_source_route=0
$SYSCTL net.ipv4.conf.all.accept_redirects=0
$SYSCTL net.ipv4.conf.all.secure_redirects=0
$SYSCTL net.ipv4.conf.all.log_martians=1
$SYSCTL net.ipv4.conf.default.accept_source_route=0
$SYSCTL net.ipv4.conf.default.accept_redirects=0
$SYSCTL net.ipv4.conf.default.secure_redirects=0
$SYSCTL net.ipv4.icmp_echo_ignore_broadcasts=1
#$SYSCTL net.ipv4.icmp_ignore_bogus_error_messages=1
$SYSCTL net.ipv4.tcp_syncookies=1
$SYSCTL net.ipv4.conf.all.rp_filter=1
$SYSCTL net.ipv4.conf.default.rp_filter=1
$SYSCTL kernel.exec-shield=1
$SYSCTL kernel.randomize_va_space=1

echo "Starting IPv4 Firewall..."
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

# load modules
modprobe ip_conntrack
modprobe ip_conntrack_ftp

[ -f "$BLOCKEDIPS" ] && BADIPS=$(egrep -v -E "^#|^$" "${BLOCKEDIPS}")

# interface connected to the Internet
PUB_IF="eth0"

#Unlimited traffic for loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# DROP all incomming traffic
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

if [ -f "${BLOCKEDIPS}" ];
then
# create a new iptables list
$IPT -N $SPAMLIST

for ipblock in $BADIPS
do
   $IPT -A $SPAMLIST -s $ipblock -j LOG --log-prefix "$SPAMDROPMSG "
   $IPT -A $SPAMLIST -s $ipblock -j DROP
done

$IPT -I INPUT -j $SPAMLIST
$IPT -I OUTPUT -j $SPAMLIST
$IPT -I FORWARD -j $SPAMLIST
fi

# Block sync
$IPT -A INPUT -i ${PUB_IF} -p tcp ! --syn -m state --state NEW  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Drop Sync"
$IPT -A INPUT -i ${PUB_IF} -p tcp ! --syn -m state --state NEW -j DROP

# Block Fragments
$IPT -A INPUT -i ${PUB_IF} -f  -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fragments Packets"
$IPT -A INPUT -i ${PUB_IF} -f -j DROP

# Block bad stuff
$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL ALL -j DROP

$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "NULL Packets"
$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL NONE -j DROP # NULL packets
$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "XMAS Packets"
$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #XMAS

$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-level 4 --log-prefix "Fin Packets Scan"
$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags FIN,ACK FIN -j DROP # FIN packet scans

$IPT  -A INPUT -i ${PUB_IF} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Allow full outgoing connection but no incomming stuff
$IPT -A INPUT -i ${PUB_IF} -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -o ${PUB_IF} -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Allow ssh
$IPT -A INPUT -i ${PUB_IF} -p tcp --destination-port 22 -j ACCEPT

# Allow ftp
$IPT -A INPUT -i ${PUB_IF} -p tcp --destination-port 21 -j ACCEPT

# Allow FTP connections @ port 21
$IPT -A INPUT  -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT  -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT

# Allow Active FTP Connections
$IPT -A INPUT -p tcp --sport 20 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 20 -m state --state ESTABLISHED -j ACCEPT

# Allow Passive FTP Connections
$IPT -A INPUT -p tcp --sport 1024: --dport 1024: -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -p tcp --sport 1024: --dport 1024:  -m state --state ESTABLISHED,RELATED -j ACCEPT


# Allow http / https (open port 80 / 443)
$IPT -A INPUT -i ${PUB_IF} -p tcp --destination-port 80 -j ACCEPT
#$IPT -A INPUT -o ${PUB_IF} -p tcp --destination-port 443 -j ACCEPT

# allow incomming ICMP ping pong stuff
$IPT -A INPUT -i ${PUB_IF} -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#$IPT -A OUTPUT -o ${PUB_IF} -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow port 53 tcp/udp (DNS Server)
$IPT -A INPUT -i ${PUB_IF} -p udp --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#$IPT -A OUTPUT -o ${PUB_IF} -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT

$IPT -A INPUT -i ${PUB_IF} -p tcp --destination-port 53 -m state --state NEW,ESTABLISHED,RELATED  -j ACCEPT
#$IPT -A OUTPUT -o ${PUB_IF} -p tcp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Open port 110 (pop3) / 143
$IPT -A INPUT -i ${PUB_IF} -p tcp --destination-port 110 -j ACCEPT
$IPT -A INPUT -i ${PUB_IF} -p tcp --destination-port 143 -j ACCEPT



##### Add your rules below ######
#

#whitelist Cloudflare's IP addresses / i'm using cloudflare as CDN/DNS
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 204.93.240.0/24 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 204.93.177.0/24 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 199.27.128.0/21 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 199.27.128.0/21 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 173.245.48.0/20 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 103.21.244.0/22 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 103.22.200.0/22 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 103.31.4.0/22 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 141.101.64.0/18 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 108.162.192.0/18 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 190.93.240.0/20 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 188.114.96.0/20 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 197.234.240.0/22 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 198.41.128.0/17 -j ACCEPT
$IPT -I INPUT -p tcp -m multiport --dports http,https -s 162.158.0.0/15 -j ACCEPT
#
##### END your rules ############

# Do not log smb/windows sharing packets - too much logging
$IPT -A INPUT -p tcp -i ${PUB_IF} --dport 137:139 -j REJECT
$IPT -A INPUT -p udp -i ${PUB_IF} --dport 137:139 -j REJECT

# log everything else and drop
$IPT -A INPUT -j LOG
$IPT -A FORWARD -j LOG
$IPT -A INPUT -j DROP

exit 0
