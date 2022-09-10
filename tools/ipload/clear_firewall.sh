sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -t nat -F
sudo iptables -t nat -P PREROUTING ACCEPT
sudo iptables -t nat -P INPUT ACCEPT
sudo iptables -t nat -P OUTPUT ACCEPT
sudo iptables -t nat -P POSTROUTING ACCEPT
sudo iptables -t mangle -F
sudo iptables -t mangle -P PREROUTING ACCEPT
sudo iptables -t mangle -P INPUT ACCEPT
sudo iptables -t mangle -P FORWARD ACCEPT
sudo iptables -t mangle -P OUTPUT ACCEPT
sudo iptables -t mangle -P POSTROUTING ACCEPT
sudo iptables -t raw -F
sudo iptables -t raw -P PREROUTING ACCEPT
sudo iptables -t raw -P OUTPUT ACCEPT
sudo iptables -t security -F
sudo iptables -t security -P INPUT ACCEPT
sudo iptables -t security -P FORWARD ACCEPT
sudo iptables -t security -P OUTPUT ACCEPT
sudo ip6tables -F
sudo ip6tables -P INPUT ACCEPT
sudo ip6tables -P FORWARD ACCEPT
sudo ip6tables -P OUTPUT ACCEPT
sudo ip6tables -t nat -F
sudo ip6tables -t nat -P PREROUTING ACCEPT
sudo ip6tables -t nat -P INPUT ACCEPT
sudo ip6tables -t nat -P OUTPUT ACCEPT
sudo ip6tables -t nat -P POSTROUTING ACCEPT
sudo ip6tables -t mangle -F
sudo ip6tables -t mangle -P PREROUTING ACCEPT
sudo ip6tables -t mangle -P INPUT ACCEPT
sudo ip6tables -t mangle -P FORWARD ACCEPT
sudo ip6tables -t mangle -P OUTPUT ACCEPT
sudo ip6tables -t mangle -P POSTROUTING ACCEPT
sudo ip6tables -t raw -F
sudo ip6tables -t raw -P PREROUTING ACCEPT
sudo ip6tables -t raw -P OUTPUT ACCEPT
sudo ip6tables -t security -F
sudo ip6tables -t security -P INPUT ACCEPT
sudo ip6tables -t security -P FORWARD ACCEPT
sudo ip6tables -t security -P OUTPUT ACCEPT
