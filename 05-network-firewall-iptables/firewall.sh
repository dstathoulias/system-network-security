#!/bin/bash
# You are NOT allowed to change the files' names!
config="config.txt"
rulesV4="rulesV4"
rulesV6="rulesV6"

function firewall() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi

    if [ "$1" = "-config"  ]; then
        # Reset current rules first to avoid duplicates
        iptables -F
        ip6tables -F
        
        while read -r line || [ -n "$line" ]; do
            # Skip empty lines or comments
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            
            # Check if entry is a raw IP (v4 or v6)
            if [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                iptables -A INPUT -s "$line" -j REJECT
                iptables -A OUTPUT -d "$line" -j REJECT
            elif [[ "$line" =~ .*:.* ]]; then
                ip6tables -A INPUT -s "$line" -j REJECT
                ip6tables -A OUTPUT -d "$line" -j REJECT
            else
                # It's a domain name; resolve and block all associated IPs [cite: 15]
                # Process IPv4
                ips_v4=$(host -t A "$line" | awk '/has address/ { print $4 }')
                for ip in $ips_v4; do
                    iptables -A INPUT -s "$ip" -j REJECT
                    iptables -A OUTPUT -d "$ip" -j REJECT
                done
                
                # Process IPv6
                ips_v6=$(host -t AAAA "$line" | awk '/has IPv6 address/ { print $5 }')
                for ip in $ips_v6; do
                    ip6tables -A INPUT -s "$ip" -j REJECT
                    ip6tables -A OUTPUT -d "$ip" -j REJECT
                done
            fi
        done < "$config"
        printf "Adblock rules configured from %s.\n" "$config"
        
    elif [ "$1" = "-save"  ]; then
        iptables-save > "$rulesV4"
        ip6tables-save > "$rulesV6"
        printf "Rules saved to %s and %s.\n" "$rulesV4" "$rulesV6"
        
    elif [ "$1" = "-load"  ]; then
        iptables-restore < "$rulesV4"
        ip6tables-restore < "$rulesV6"
        printf "Rules loaded from %s and %s.\n" "$rulesV4" "$rulesV6"
        
    elif [ "$1" = "-reset"  ]; then
        # Flush all rules and delete user-defined chains 
        iptables -F
        iptables -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        
        ip6tables -F
        ip6tables -X
        ip6tables -P INPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ip6tables -P OUTPUT ACCEPT
        printf "Firewall reset to default (ACCEPT ALL).\n"
        
    elif [ "$1" = "-list"  ]; then
        printf "--- IPv4 Rules ---\n"
        iptables -L -n -v 
        printf "\n--- IPv6 Rules ---\n"
        ip6tables -L -n -v
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple firewall mechanism. It rejects connections from specific domain names or IP addresses using iptables/ip6tables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -config\t  Configure adblock rules based on the domain names and IPs of '$config' file.\n"
        printf "  -save\t\t  Save rules to '$rulesV4' and '$rulesV6'  files.\n"
        printf "  -load\t\t  Load rules from '$rulesV4' and '$rulesV6' files.\n"
        printf "  -list\t\t  List current rules for IPv4 and IPv6.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

firewall $1
exit 0