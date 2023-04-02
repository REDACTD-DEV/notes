# Network Forensics

## IPV4 Header
| Field | Size | Description |
|-------|------|-------------|
| Version | 4 bits | Indicates the version of the IP protocol being used. In IPv4, this field is always set to 4. |
| Internet Header Length (IHL) | 4 bits | Specifies the length of the IPv4 header in 32-bit words. This field is necessary because the header can have variable length options, which means the length of the header can vary. |
| Type of Service (TOS) | 8 bits | Originally designed to specify quality of service parameters, this field is now generally unused. |
| Total Length | 16 bits | Specifies the total length of the IPv4 datagram, including the header and data, in bytes. |
| Identification | 16 bits | Used to identify fragments of a larger datagram. |
| Flags | 3 bits | Used to control fragmentation. The three bits are: a reserved bit (always 0), the Don't Fragment (DF) bit, and the More Fragments (MF) bit. |
| Fragment Offset | 13 bits | Used to indicate the offset of the current fragment relative to the beginning of the original datagram. |
| Time to Live (TTL) | 8 bits | Specifies the maximum number of hops the packet can take before it is discarded. |
| Protocol | 8 bits | Specifies the protocol used in the data portion of the IPv4 datagram (e.g., TCP, UDP, ICMP). |
| Header Checksum | 16 bits | Used to detect errors in the header. |
| Source IP Address | 32 bits | Specifies the source IP address of the datagram. |
| Destination IP Address | 32 bits | Specifies the destination IP address of the datagram. |
| Options | variable length | Optional fields that can be used to provide additional information about the datagram, such as security or routing information. |

## IPV6 Header
| Field | Size | Description |
|-------|------|-------------|
| Version | 4 bits | Indicates the version of the IP protocol being used. In IPv6, this field is always set to 6. |
| Traffic Class | 8 bits | Specifies the priority and type of service for the packet, similar to the TOS field in IPv4. |
| Flow Label | 20 bits | Used to group packets that belong to the same flow, such as a video stream or file transfer. |
| Payload Length | 16 bits | Specifies the length of the data portion of the IPv6 packet, not including the header. |
| Next Header | 8 bits | Specifies the protocol used in the data portion of the IPv6 packet (e.g., TCP, UDP, ICMPv6). |
| Hop Limit | 8 bits | Specifies the maximum number of hops the packet can take before it is discarded, similar to the TTL field in IPv4. |
| Source Address | 128 bits | Specifies the source IP address of the packet. |
| Destination Address | 128 bits | Specifies the destination IP address of the packet. |
| Extension Headers | variable length | Optional headers that can be used to provide additional information about the packet, such as security or routing information. |
| Payload | variable length | The data portion of the IPv6 packet, not including the header. |
