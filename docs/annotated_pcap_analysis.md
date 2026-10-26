# Annotated PCAP Analysis (Week 1 deliverable)

**Capture:** `sample_data/beacon_sim.pcap` - a SIMULATED scenario (synthetic traffic, not real malware).
**Size:** 52 KB, 432 packets, 2098 s (35.0 min).

## 1. First connection, packet by packet

| # | Time | Direction | TCP flags | Payload bytes | What it means |
|---|---|---|---|---|---|
| 1 | +0.000s | 192.168.1.50:41853 -> 203.0.113.50:8443 | S | 0 | TCP handshake 1/3: client sends SYN (window 64240, MSS 1460) |
| 2 | +0.020s | 203.0.113.50:8443 -> 192.168.1.50:41853 | SA | 0 | TCP handshake 2/3: server accepts with SYN-ACK |
| 3 | +0.040s | 192.168.1.50:41853 -> 203.0.113.50:8443 | A | 0 | ACK (handshake 3/3 or acknowledgement of data) |
| 4 | +0.050s | 192.168.1.50:41853 -> 203.0.113.50:8443 | PA | 150 | TLS ClientHello. SNI visible: c2-sim.example; offers TLS 1.3; JA3 7134d4c61a... |
| 5 | +0.070s | 203.0.113.50:8443 -> 192.168.1.50:41853 | A | 0 | ACK (handshake 3/3 or acknowledgement of data) |
| 6 | +0.080s | 203.0.113.50:8443 -> 192.168.1.50:41853 | PA | 305 | TLS record: encrypted application data (content not inspectable) |
| 7 | +0.100s | 192.168.1.50:41853 -> 203.0.113.50:8443 | A | 0 | ACK (handshake 3/3 or acknowledgement of data) |
| 8 | +0.110s | 192.168.1.50:41853 -> 203.0.113.50:8443 | PA | 145 | TLS record: encrypted application data (content not inspectable) |
| 9 | +0.130s | 203.0.113.50:8443 -> 192.168.1.50:41853 | A | 0 | ACK (handshake 3/3 or acknowledgement of data) |
| 10 | +0.140s | 192.168.1.50:41853 -> 203.0.113.50:8443 | FA | 0 | FIN: graceful close |
| 11 | +0.160s | 203.0.113.50:8443 -> 192.168.1.50:41853 | FA | 0 | FIN: graceful close |
| 12 | +0.180s | 192.168.1.50:41853 -> 203.0.113.50:8443 | A | 0 | ACK (handshake 3/3 or acknowledgement of data) |
| 13 | +58.981s | 192.168.1.50:55720 -> 203.0.113.50:8443 | S | 0 | TCP handshake 1/3: client sends SYN (window 64240, MSS 1460) |
| 14 | +59.001s | 203.0.113.50:8443 -> 192.168.1.50:55720 | SA | 0 | TCP handshake 2/3: server accepts with SYN-ACK |

Open the same file in Wireshark and apply `tcp.stream eq 0` to see this connection. Apply `tls.handshake.type == 1` to list every ClientHello with its SNI.

## 2. Zoom out: what the whole capture looks like

* 36 flows, all from `192.168.1.50` to `203.0.113.50:8443/TCP`, one new connection about every minute.
* Each connection is tiny (677 B out / 575 B in on average) and nearly identical in size.
* The TLS SNI is `c2-sim.example` (a reserved, non-resolvable name) and the JA3 hash is identical in every handshake: the same client software made every connection.

## 3. How the engine scored it

**Periodic connections to 203.0.113.50:8443 (beacon-like timing)** - severity **High**, confidence **High**, evidence strength **Heuristic**.

* 36 TCP connections from 192.168.1.50 to 203.0.113.50:8443 between 2025-10-09 08:53:41 UTC and 2025-10-09 09:28:38 UTC.
* Interval mean 59.92s, median 59.96s, std 1.30s, CV 0.022; 100% of intervals within +/-20% of the median.
* Mean bytes per connection: 677 B out / 575 B in (size CV out 0.00, in 0.00).
* 36 of 36 connections received a reply. First start times: 08:53:41, 08:54:40, 08:55:39, 08:56:38, 08:57:38.
* Scoring signals (5): external destination=True, non-standard port=True, consistent sizes=True, >=20 connections=True, very regular (CV<0.1)=True.

## 4. How an analyst should interpret it

* Observed fact: regular, small, uniform connections to one external address on a non-standard port.
* Hypothesis (needs validation): malware check-in. Alternatives: a monitoring agent, a custom app heartbeat, a VPN keep-alive.
* Next evidence to collect: which process on `192.168.1.50` owns these sockets (EDR/Sysmon), what the destination is (threat intel, WHOIS, other hosts contacting it), whether the host's other behaviour changed at the same time.
* Because the payload is encrypted, the capture cannot show what was exchanged.

## 5. Baseline traffic summary (this capture)

| Metric | Value |
|---|---|
| packets | 432 |
| total_bytes | 45072 |
| duration_s | 2097.51 |
| avg_packets_per_s | 0.21 |
| avg_packet_size | 104.3 |
| unique_hosts | 2 |
| internal_hosts | 1 |
| external_hosts | 1 |
| flows | 36 |
| tcp_packets | 432 |
| udp_packets | 0 |
| icmp_packets | 0 |
| top_protocol | HTTPS-Alt |
| top_talker | 192.168.1.50 (24.37 KB sent) |
| top_dst_port | TCP/8443 |
