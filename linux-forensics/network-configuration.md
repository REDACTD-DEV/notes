| File Name                               | Description                                                                                              |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| /etc/dnsmasq.conf                       | the configuration file for DNS forwarder server and DHCP server if it is implemented in the investigated host. |
| /etc/host.conf                          | the configuration file for local DNS name assignment.                                                    |
| /etc/network/interfaces                 | the configuration file for network setup (dynamic or static IP assignment as well as scripts running when the interface is “up” or “down”). |
| /etc/resolv.conf                        | the configuration file for DNS                                                                           |
| /etc/resolvconf/run/resolv.conf         | the configuration file for DNS                                                                           |
| /etc/wireguard/                         | wireguard configuration                                                                                   |
| /etc/wpa_supplicant/*.conf              | contains SSID configuration to which the Linux machine will automatically connect when the Wi-Fi signal is in the vicinity. |
| /var/log/iptables.log                   | Contains records of firewall activity logged by the iptables firewall                                   |
| /var/log/openvpn.log                    | Contains records of VPN connections and disconnections made using OpenVPN                                |
| /var/log/snort/*                        | Contains records of network traffic monitored by the Snort intrusion detection system                    |
| /var/log/squid/access.log               | Contains records of HTTP requests made through the Squid proxy server, including client IP addresses, requested URLs, and user agents |
