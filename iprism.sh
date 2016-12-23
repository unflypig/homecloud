#!/bin/sh

#######################################################################
# (1) run process from superuser root (less security)
# (0) run process from unprivileged user "nobody" (more security)
SVC_ROOT=0

# process priority (0-normal, 19-lowest)
SVC_PRIORITY=0
#######################################################################

SVC_NAME="iPrism"
SVC_REDIR_PATH="/usr/bin/ss-redir"
SVC_PDNSD_PATH="/usr/bin/pdnsd"

dir_dnsmasq_d="/tmp/dnsmasq.d"
user_dnsmasq_conf_ss="$dir_dnsmasq_d/shadowsocks.conf"
dir_pdnsd="/var/pdnsd"

func_start()
{
    ss_conf="/etc/shadowsocks.json"
    pdnsd_conf="/etc_ro/pdnsd0.conf"
    ss_whitelist="/etc_ro/whitelist0.conf"

# Make sure already running
    if [ -n "`pidof ss-redir`" -a -n "`pidof pdnsd`" ] ; then
        return 0
    fi

    echo -n "Starting $SVC_NAME:."

    REDIR_PID="/var/run/ss-redir.pid"

    # create dnsmasq.conf for shadowsocks
    [ ! -d "$dir_dnsmasq_d" ] && mkdir -p -m 755 "$dir_dnsmasq_d"
    # create /var/pdnsd for pdnsd
    [ ! -d "$dir_pdnsd" ] && mkdir -p -m 755 "$dir_pdnsd"

    cat > "$user_dnsmasq_conf_ss" <<EOF
# Here Comes The System Defined

EOF

    grep -Ev "^$|^#.*$" $ss_whitelist | while read line
    do
        if [ `echo ${line} | egrep '^[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}(/([[:digit:]]{1,2})|)$'` ]; then
            ipset test ss_ip_include ${line} 2>/dev/null
            if [ $? -ne 0 ]; then
                ipset add ss_ip_include ${line}
            fi
        else
            echo "server=/.${line}/127.0.0.1#1053" >> "$user_dnsmasq_conf_ss"
            echo "ipset=/.${line}/ss_ip_include" >> "$user_dnsmasq_conf_ss"
        fi
    done

    cat >> "$user_dnsmasq_conf_ss" <<EOF


# Here Comes The User Defined

EOF

    whitelist_num=`nvram get whitelist_num`
    [ -n "$whitelist_num" ] && for i in $(seq 0 `expr $whitelist_num - 1`) ; do
        whitelist_domain=`nvram get whitelist_domain$i`

        if [ `echo ${whitelist_domain} | egrep '^[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}(/([[:digit:]]{1,2})|)$'` ]; then
            ipset test ss_ip_include $whitelist_domain 2>/dev/null
            if [ $? -ne 0 ]; then
                ipset add ss_ip_include $whitelist_domain
            fi
        else
            echo "server=/.$whitelist_domain/127.0.0.1#1053" >> "$user_dnsmasq_conf_ss"
            echo "ipset=/.$whitelist_domain/ss_ip_include" >> "$user_dnsmasq_conf_ss"
        fi
    done
    chmod 644 "$user_dnsmasq_conf_ss"
    /sbin/restart_dhcpd

    hash_nets="8.8.8.8 8.8.4.4"
    for i in $hash_nets
    do
        ipset test ss_ip_include ${i} 2>/dev/null
        if [ $? -ne 0 ]; then
            ipset add ss_ip_include ${i}
        fi
    done

    func_enable 

    $SVC_REDIR_PATH -c $ss_conf -f $REDIR_PID
    $SVC_PDNSD_PATH -c $pdnsd_conf -d

    if [ $? -eq 0 ] ; then
        echo "[  OK  ]"
        logger -t "$SVC_NAME" "daemon is started"
    else
        echo "[FAILED]"
    fi
}

func_stop()
{
    # Make sure not running
    if [ -z "`pidof ss-redir`" ] ; then
        return 0
    fi

    echo -n "Stopping $SVC_NAME:."

    # stop daemon
    killall -q ss-redir
    killall -q pdnsd

    func_disable

# clear dnsmasq.conf for shadowsocks
    [ ! -d "$dir_dnsmasq_d" ] && mkdir -p -m 755 "$dir_dnsmasq_d"
    cat > "$user_dnsmasq_conf_ss" <<EOF

EOF
    chmod 644 "$user_dnsmasq_conf_ss"
    /sbin/restart_dhcpd

    # gracefully wait max 15 seconds while ss-redir stopped
    i=0
    while [ -n "`pidof ss-redir`" -o -n "`pidof pdnsd`" ] && [ $i -le 15 ] ; do
        echo -n "."
        i=$(( $i + 1 ))
        sleep 1
    done

    redir_pid=`pidof ss-redir`
    pdnsd_pid=`pidof pdnsd`
    if [ -n "$redir_pid" -o -n "$pdnsd_pid" ] ; then
        # force kill (hungup?)
        if [ -n "$redir_pid" ]; then
            kill -9 "$redir_pid"
        fi
        if [ -n "$pdnsd_pid" ]; then
            kill -9 "$pdnsd_pid"
        fi
        sleep 1
        echo "[KILLED]"
        logger -t "$SVC_NAME" "Cannot stop: Timeout reached! Force killed."
    else
        echo "[  OK  ]"
    fi
}

func_enable()
{
    iptables -t nat -C PREROUTING -p udp -d 8.8.4.4 --dport 53 -j REDIRECT --to-ports 53
    if [ $? -eq 1 ] ; then
        iptables -t nat -A PREROUTING -p udp -d 8.8.4.4 --dport 53 -j REDIRECT --to-ports 53
    fi

    iptables -t nat -C PREROUTING -p udp -d 8.8.8.8 --dport 53 -j REDIRECT --to-ports 53
    if [ $? -eq 1 ] ; then
        iptables -t nat -A PREROUTING -p udp -d 8.8.8.8 --dport 53 -j REDIRECT --to-ports 53
    fi
    
    iptables -t nat -C PREROUTING -p tcp -m set --match-set ss_ip_include dst -j REDIRECT --to-port 1080
    if [ $? -eq 1 ] ; then
        iptables -t nat -A PREROUTING -p tcp -m set --match-set ss_ip_include dst -j REDIRECT --to-port 1080
    fi
    iptables -t nat -C OUTPUT -p tcp -m set --match-set ss_ip_include dst -j REDIRECT --to-port 1080
    if [ $? -eq 1 ] ; then
        iptables -t nat -A OUTPUT -p tcp -m set --match-set ss_ip_include dst -j REDIRECT --to-port 1080
    fi
}

func_disable()
{
    iptables -t nat -C PREROUTING -p tcp -m set --match-set ss_ip_include dst -j REDIRECT --to-port 1080
    if [ $? -eq 0 ] ; then
        iptables -t nat -D PREROUTING -p tcp -m set --match-set ss_ip_include dst -j REDIRECT --to-port 1080
    fi
    iptables -t nat -C OUTPUT -p tcp -m set --match-set ss_ip_include dst -j REDIRECT --to-port 1080
    if [ $? -eq 0 ] ; then
        iptables -t nat -D OUTPUT -p tcp -m set --match-set ss_ip_include dst -j REDIRECT --to-port 1080
    fi

    iptables -t nat -C PREROUTING -p udp -d 8.8.4.4 --dport 53 -j REDIRECT --to-ports 53
    if [ $? -eq 0 ] ; then
        iptables -t nat -D PREROUTING -p udp -d 8.8.4.4 --dport 53 -j REDIRECT --to-ports 53
    fi

    iptables -t nat -C PREROUTING -p udp -d 8.8.8.8 --dport 53 -j REDIRECT --to-ports 53
    if [ $? -eq 0 ] ; then
        iptables -t nat -D PREROUTING -p udp -d 8.8.8.8 --dport 53 -j REDIRECT --to-ports 53
    fi
 
}

case "$1" in
start)
    func_start
    ;;
stop)
    func_stop
    ;;
restart)
    func_stop
    func_start
    ;;
enable)
    func_enable
    ;;
disable)
    func_disable
    ;;
*)
    echo "Usage: $0 {start|stop|restart|enable|disable}"
    exit 1
    ;;
esac
