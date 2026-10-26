# Wireshark Filter Cheat Sheet (Week 1 deliverable)

Type these into the Wireshark **display filter** bar (green = valid, red = syntax problem). Replace the example addresses and names with your own.

| Topic | Purpose | Display filter |
|---|---|---|
| DNS | All DNS traffic | `dns` |
| DNS | DNS queries only | `dns.flags.response == 0` |
| DNS | NXDOMAIN responses | `dns.flags.rcode == 3` |
| DNS | Long query names | `dns.qry.name.len > 50` |
| DNS | TXT queries (tunneling candidates) | `dns.qry.type == 16` |
| HTTP | HTTP requests | `http.request` |
| HTTP | POST requests | `http.request.method == "POST"` |
| HTTP | Filter by Host | `http.host contains "example.com"` |
| HTTP | Filter by user-agent | `http.user_agent contains "curl"` |
| TLS | ClientHello (SNI visible) | `tls.handshake.type == 1` |
| TLS | Filter by SNI | `tls.handshake.extensions_server_name contains "example"` |
| TLS | JA3 hash | `tls.handshake.ja3 == "<hash>"` |
| TCP | TCP resets | `tcp.flags.reset == 1` |
| TCP | SYN packets (no ACK) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| TCP | SYN-ACK packets | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| TCP | Retransmissions | `tcp.analysis.retransmission` |
| IP | Specific IP (either direction) | `ip.addr == 192.168.1.10` |
| IP | Source/destination pair | `ip.src == 192.168.1.10 && ip.dst == 203.0.113.50` |
| Services | SMB | `smb || smb2` |
| Services | SSH | `tcp.port == 22` |
| Services | RDP | `tcp.port == 3389` |
| ICMP | ICMP echo requests | `icmp.type == 8` |

## Capture filters (BPF) - applied *while capturing*

| Goal | Capture filter |
|---|---|
| One host | `host 192.168.1.10` |
| DNS only | `udp port 53` |
| Web traffic | `tcp port 80 or tcp port 443` |
| Everything except broadcast/multicast | `not broadcast and not multicast` |
| A subnet | `net 192.168.1.0/24` |

Capture filters cannot be changed afterwards and drop everything else, so prefer display filters when investigating an existing PCAP.

## Useful workflow tips
* Right-click a packet > **Follow > TCP Stream** to read one conversation; `tcp.stream eq N` to filter to it.
* **Statistics > Conversations / Endpoints / Protocol Hierarchy** reproduce the dashboard's top-talker and protocol views.
* **Statistics > I/O Graph** with the filter `ip.addr == A && ip.addr == B` makes regular beaconing visible as evenly spaced spikes.
* The dashboard's **Alerts and Anomalies** page prints ready-to-paste filters for each alert (also stored in the JSON report).
* TLS: when SNI is not visible (e.g. encrypted ClientHello or session resumption), `tls.handshake.extensions_server_name` will be empty; fall back to IP-based filters.
