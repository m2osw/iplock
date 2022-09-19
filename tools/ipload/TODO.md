

# IPv4 rules to block by default

IPv4 rules found here:
https://kromey.us/2016/08/setting-up-an-iptables-firewall-part-5-810.html

    *filter
    :INPUT DROP [0:0]
    :FORWARD ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    :attacks - [0:0]
    :blacklist - [0:0]
    :bl_drop - [0:0]
    :icmp - [0:0]
    :martians - [0:0]
    :portknock - [0:0]
    :services - [0:0]
    -A INPUT -p icmp -j icmp
    -A INPUT -i lo -m comment --comment "Free reign for loopback" -j ACCEPT
    -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    -A INPUT -m state --state INVALID -j DROP
    -A INPUT -m comment --comment "Guard SSH with port knocking" -j portknock
    -A INPUT -m recent --name blacklist --rcheck --seconds 3600 -j blacklist
    -A INPUT -m recent --name blacklist --remove
    -A INPUT -m comment --comment "Handle common attacks" -j attacks
    -A INPUT -m comment --comment "Filter martians" -j martians
    -A INPUT -m comment --comment "Open service ports" -j services
    -A INPUT -j blacklist
    -A attacks -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m comment --comment "NULL packets" -j bl_drop
    -A attacks -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "SYN flag checking" -j bl_drop
    -A attacks -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -m comment --comment "XMAS packets" -j bl_drop
    -A attacks -p tcp -m tcp --syn -m recent --name synflood --set
    -A attacks -p tcp -m tcp --syn -m recent --name synflood --rcheck --seconds 1 --hitcount 60 -j bl_drop
    -A blacklist -p tcp -m tcp --dport 21 -m comment --comment "FTP" -j bl_drop
    -A blacklist -p tcp -m tcp --dport 23 -m comment --comment "Telnet" -j bl_drop
    -A blacklist -p tcp -m tcp --dport 25 -m comment --comment "SMTP" -j bl_drop
    -A blacklist -p tcp -m tcp --dport 139 -m comment --comment "SMB" -j bl_drop
    -A blacklist -p tcp -m tcp --dport 3389 -m comment --comment "RDP" -j bl_drop
    -A blacklist -j DROP
    -A bl_drop -m recent --name blacklist --set -m comment --comment "Blacklist the source" -j DROP
    -A icmp -m limit --limit 1/s --limit-burst 4 -j ACCEPT
    -A icmp -j DROP
    -A martians --source 0.0.0.0/8 -m comment --comment "'This' network" -j DROP
    -A martians --source 10.0.0.0/8 -m comment --comment "Private-use networks" -j DROP
    -A martians --source 100.64.0.0/10 -m comment --comment "Carrier-grade NAT" -j DROP
    -A martians --source 127.0.0.0/8 -m comment --comment "Loopback" -j DROP
    -A martians --source 169.254.0.0/16 -m comment --comment "Link local" -j DROP
    -A martians --source 172.16.0.0/12 -m comment --comment "Private-use networks" -j DROP
    -A martians --source 192.0.0.0/24 -m comment --comment "IETF protocol assignments" -j DROP
    -A martians --source 192.0.2.0/24 -m comment --comment "TEST-NET-1" -j DROP
    -A martians --source 192.168.0.0/16 -m comment --comment "Private-use networks" -j DROP
    -A martians --source 198.18.0.0/15 -m comment --comment "Network interconnect device benchmark testing" -j DROP
    -A martians --source 198.51.100.0/24 -m comment --comment "TEST-NET-2" -j DROP
    -A martians --source 203.0.113.0/24 -m comment --comment "TEST-NET-3" -j DROP
    -A martians --source 224.0.0.0/4 -m comment --comment "Multicast" -j DROP
    -A martians --source 240.0.0.0/4 -m comment --comment "Reserved for future use" -j DROP
    -A martians --source 255.255.255.255/32 -m comment --comment "Limited broadcast" -j DROP
    -A portknock -m recent --rcheck --seconds 3600 --name knock3 -m recent --remove --name blacklist
    -A portknock -p tcp -m tcp --dport 22 -m recent --rcheck --seconds 3600 --name knock3 -j ACCEPT
    -A portknock -p tcp -m tcp --dport 3456 -m recent --rcheck --seconds 10 --name knock2 -m recent --set --name knock3
    -A portknock -m recent --remove --name knock2
    -A portknock -p tcp -m tcp --dport 2345 -m recent --rcheck --seconds 10 --name knock1 -m recent --set --name knock2
    -A portknock -m recent --remove --name knock1
    -A portknock -p tcp -m tcp --dport 1234 --set --name knock1
    -A services -p tcp -m tcp --dport 80 -m comment --comment "HTTP" -j ACCEPT
    -A services -p tcp -m tcp --dport 443 -m comment --comment "HTTPS" -j ACCEPT
    COMMIT


# IPv6 rules to block by default

IPv6 rules found here:
https://kromey.us/2016/08/setting-up-an-iptables-firewall-part-6-818.html

    *filter
    :INPUT DROP [0:0]
    :FORWARD ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    :attacks - [0:0]
    :blacklist - [0:0]
    :bl_drop - [0:0]
    :icmp - [0:0]
    :martians - [0:0]
    :portknock - [0:0]
    :services - [0:0]
    -A INPUT -p icmp -j icmp
    -A INPUT -i lo -m comment --comment "Free reign for loopback" -j ACCEPT
    -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    -A INPUT -m state --state INVALID -j DROP
    -A INPUT -m comment --comment "Guard SSH with port knocking" -j portknock
    -A INPUT -m recent --name blacklist --rcheck --seconds 3600 -j blacklist
    -A INPUT -m recent --name blacklist --remove
    -A INPUT -m comment --comment "Handle common attacks" -j attacks
    -A INPUT -m comment --comment "Filter martians" -j martians
    -A INPUT -m comment --comment "Open service ports" -j services
    -A INPUT -j blacklist
    -A attacks -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m comment --comment "NULL packets" -j bl_drop
    -A attacks -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment "SYN flag checking" -j bl_drop
    -A attacks -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -m comment --comment "XMAS packets" -j bl_drop
    -A attacks -p tcp -m tcp --syn -m recent --name synflood --set
    -A attacks -p tcp -m tcp --syn -m recent --name synflood --rcheck --seconds 1 --hitcount 60 -j bl_drop
    -A blacklist -p tcp -m tcp --dport 21 -m comment --comment "FTP" -j bl_drop
    -A blacklist -p tcp -m tcp --dport 23 -m comment --comment "Telnet" -j bl_drop
    -A blacklist -p tcp -m tcp --dport 25 -m comment --comment "SMTP" -j bl_drop
    -A blacklist -p tcp -m tcp --dport 139 -m comment --comment "SMB" -j bl_drop
    -A blacklist -p tcp -m tcp --dport 3389 -m comment --comment "RDP" -j bl_drop
    -A blacklist -j DROP
    -A bl_drop -m recent --name blacklist --set -m comment --comment "Blacklist the source" -j DROP
    -A icmp -m limit --limit 1/s --limit-burst 4 -j ACCEPT
    -A icmp -j DROP
    -A martians --source ::/96 -m comment --comment "IPv4-compatible IPv6 address ¿ deprecated by RFC4291" -j DROP
    -A martians --source ::/128 -m comment --comment "Unspecified address" -j DROP
    -A martians --source ::1/128 -m comment --comment "Local host loopback address" -j DROP
    -A martians --source ::ffff:0.0.0.0/96 -m comment --comment "IPv4-mapped addresses" -j DROP
    -A martians --source ::224.0.0.0/100 -m comment --comment "Compatible address (IPv4 format)" -j DROP
    -A martians --source ::127.0.0.0/104 -m comment --comment "Compatible address (IPv4 format)" -j DROP
    -A martians --source ::0.0.0.0/104 -m comment --comment "Compatible address (IPv4 format)" -j DROP
    -A martians --source ::255.0.0.0/104 -m comment --comment "Compatible address (IPv4 format)" -j DROP
    -A martians --source 0000::/8 -m comment --comment "Pool used for unspecified, loopback and embedded IPv4 addresses" -j DROP
    -A martians --source 0200::/7 -m comment --comment "OSI NSAP-mapped prefix set (RFC4548) ¿ deprecated by RFC4048" -j DROP
    -A martians --source 3ffe::/16 -m comment --comment "Former 6bone, now decommissioned" -j DROP
    -A martians --source 2001:db8::/32 -m comment --comment "Reserved by IANA for special purposes and documentation" -j DROP
    -A martians --source 2002:e000::/20 -m comment --comment "Invalid 6to4 packets (IPv4 multicast)" -j DROP
    -A martians --source 2002:7f00::/24 -m comment --comment "Invalid 6to4 packets (IPv4 loopback)" -j DROP
    -A martians --source 2002:0000::/24 -m comment --comment "Invalid 6to4 packets (IPv4 default)" -j DROP
    -A martians --source 2002:ff00::/24 -m comment --comment "Invalid 6to4 packets" -j DROP
    -A martians --source 2002:0a00::/24 -m comment --comment "Invalid 6to4 packets (IPv4 private 10.0.0.0/8 network)" -j DROP
    -A martians --source 2002:ac10::/28 -m comment --comment "Invalid 6to4 packets (IPv4 private 172.16.0.0/12 network)" -j DROP
    -A martians --source 2002:c0a8::/32 -m comment --comment "Invalid 6to4 packets (IPv4 private 192.168.0.0/16 network)" -j DROP
    -A martians --source fc00::/7 -m comment --comment "Unicast Unique Local Addresses (ULA) ¿ RFC 4193" -j DROP
    -A martians --source fe80::/10 -m comment --comment "Link-local Unicast" -j DROP
    -A martians --source fec0::/10 -m comment --comment "Site-local Unicast ¿ deprecated by RFC 3879 (replaced by ULA)" -j DROP
    -A martians --source ff00::/8 -m comment --comment "Multicast" -j DROP
    -A portknock -m recent --rcheck --seconds 3600 --name knock3 -m recent --remove --name blacklist
    -A portknock -p tcp -m tcp --dport 22 -m recent --rcheck --seconds 3600 --name knock3 -j ACCEPT
    -A portknock -p tcp -m tcp --dport 3456 -m recent --rcheck --seconds 10 --name knock2 -m recent --set --name knock3
    -A portknock -m recent --remove --name knock2
    -A portknock -p tcp -m tcp --dport 2345 -m recent --rcheck --seconds 10 --name knock1 -m recent --set --name knock2
    -A portknock -m recent --remove --name knock1
    -A portknock -p tcp -m tcp --dport 1234 --set --name knock1
    -A services -p tcp -m tcp --dport 80 -m comment --comment "HTTP" -j ACCEPT
    -A services -p tcp -m tcp --dport 443 -m comment --comment "HTTPS" -j ACCEPT
    COMMIT

