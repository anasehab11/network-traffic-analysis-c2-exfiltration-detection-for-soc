# Network Protocol Map and Baseline Summary (Week 1 deliverables)

Source: `sample_data/demo_combined_sim.pcap` (SIMULATED; five synthetic scenarios merged). The dashboard draws the same map as a
Sankey diagram on **Traffic Overview**; this file is the static, text version.

## Protocol map (top flows: source -> service -> destination)

| Source | Service | Destination | Flows | Bytes |
|---|---|---|---|---|
| 192.168.1.88 | DNS | 192.168.1.1 | 345 | 82.36 KB |
| 192.168.1.66 | TCP | 192.168.1.20 | 183 | 20.50 KB |
| 192.168.1.50 | TLS | 203.0.113.50 | 36 | 45.07 KB |
| 192.168.1.10 | DNS | 192.168.1.1 | 25 | 4.58 KB |
| 192.168.1.10 | NTP | 203.0.113.123 | 12 | 2.16 KB |
| 192.168.1.10 | TLS | 198.51.100.20 | 7 | 22.44 KB |
| 192.168.1.10 | TLS | 198.51.100.30 | 6 | 19.24 KB |
| 192.168.1.66 | HTTP | 192.168.1.20 | 6 | 3.04 KB |
| 192.168.1.10 | TLS | 198.51.100.10 | 4 | 12.82 KB |
| 192.168.1.10 | TLS | 198.51.100.21 | 4 | 12.83 KB |
| 192.168.1.10 | TLS | 198.51.100.11 | 3 | 9.62 KB |
| 192.168.1.66 | NetBIOS | 192.168.1.20 | 2 | 224 B |
| 192.168.1.66 | SSH | 192.168.1.20 | 2 | 332 B |
| 192.168.1.66 | SMB | 192.168.1.20 | 2 | 278 B |
| 192.168.1.66 | DHCP | 192.168.1.20 | 2 | 224 B |

## Protocol distribution

| Protocol | Packets | Bytes |
|---|---|---|
| HTTP-Alt | 3005 | 2.96 MB |
| DNS | 744 | 87.23 KB |
| TCP | 366 | 20.50 KB |
| HTTPS-Alt | 326 | 17.75 KB |
| HTTPS | 240 | 13.06 KB |
| TLS | 204 | 91.33 KB |
| HTTP | 58 | 4.67 KB |
| SMB | 48 | 2.76 KB |
| ICMP | 40 | 2.00 KB |
| NTP | 26 | 2.27 KB |

## Top talkers (by bytes sent)

| Host | Scope | Bytes sent |
|---|---|---|
| 192.168.1.77 | internal | 2.91 MB |
| 198.51.100.25 | external | 54.15 KB |
| 192.168.1.1 | internal | 43.97 KB |
| 192.168.1.88 | internal | 41.18 KB |
| 192.168.1.50 | internal | 24.37 KB |
| 192.168.1.10 | internal | 21.99 KB |
| 203.0.113.50 | external | 20.70 KB |
| 192.168.1.66 | internal | 18.04 KB |

## Top destination ports

| Port | Service | Flows |
|---|---|---|
| UDP/53 | DNS | 371 |
| TCP/445 | SMB | 42 |
| TCP/8443 | TLS | 37 |
| TCP/443 | TLS | 24 |
| UDP/123 | NTP | 12 |
| TCP/80 | HTTP | 7 |
| TCP/8080 | HTTP-Alt | 2 |
| TCP/22 | SSH | 2 |

## TCP flag analysis

| Flag | Packets |
|---|---|
| SYN (connection attempts) | 317 |
| SYN-ACK (accepted) | 72 |
| RST (reset / refused) | 212 |
| FIN (graceful close) | 131 |

A high RST count relative to SYN-ACK (as here) means many connection attempts were refused. In this capture that comes from the simulated scan.

## Baseline summary

| Metric | Value |
|---|---|
| packets | 5098 |
| total_bytes | 3204747 |
| duration_s | 2117.88 |
| avg_packets_per_s | 2.41 |
| avg_packet_size | 628.6 |
| unique_hosts | 84 |
| internal_hosts | 75 |
| external_hosts | 9 |
| flows | 730 |
| tcp_packets | 4292 |
| udp_packets | 766 |
| icmp_packets | 40 |
| top_protocol | HTTP-Alt |
| top_talker | 192.168.1.77 (2.91 MB sent) |
| top_dst_port | UDP/53 |

In a real environment, capture a quiet representative period first and keep this summary as the baseline; deviations in top talkers, ports or protocol mix are
then easy to spot.
