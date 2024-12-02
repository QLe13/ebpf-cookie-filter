## Internal Code Documentation: eBPF TCP Packet Counter and Sampler

This document details the implementation of an eBPF program designed to count TCP packets and sample TCP packet information for analysis.  The program processes packets in the XDP (eXpress Data Path) context, allowing for high-performance packet inspection without copying data to kernel space. The program focuses on TCP packets but the structure is designed to accommodate other protocols in the future.

### Table of Contents

1. [Introduction](#introduction)
2. [Data Structures](#data-structures)
    * [struct packet_info](#struct-packet_info)
3. [BPF Maps and Arrays](#bpf-maps-and-arrays)
    * [packet_count](#packet_count)
    * [sample_counter](#sample_counter)
4. [BPF Perf Buffer](#bpf-perf-buffer)
    * [packet_events](#packet_events)
5. [Core Function: count_tcp_packets](#core-function-count_tcp_packets)
    * [Packet Processing Pipeline](#packet-processing-pipeline)
    * [TCP Packet Handling](#tcp-packet-handling)
    * [Packet Counting](#packet-counting)
    * [Sampling and Logging](#sampling-and-logging)
6. [Conclusion](#conclusion)



## <a name="introduction"></a>1. Introduction

This document details the implementation of an eBPF program designed to count TCP packets and sample TCP packet information for analysis.  The program processes packets in the XDP (eXpress Data Path) context, allowing for high-performance packet inspection without copying data to kernel space. The program focuses on TCP packets but the structure is designed to accommodate other protocols in the future.

## <a name="data-structures"></a>2. Data Structures

### <a name="struct-packet_info"></a>struct packet_info

| Field Name    | Type       | Description                                  |
|---------------|------------|----------------------------------------------|
| `src_ip`      | `__u32`    | Source IP address.                           |
| `dst_ip`      | `__u32`    | Destination IP address.                        |
| `src_port`    | `__u16`    | Source port.                                 |
| `dst_port`    | `__u16`    | Destination port.                             |
| `protocol`    | `__u8`     | IP protocol (e.g., IPPROTO_TCP, IPPROTO_UDP). |
| `packet_type` | `__u8`     | Packet type (0: TCP, 1: UDP, 2: ICMP, etc.). |
| `packet_len`  | `__u32`    | Total packet length.                         |
| `seq_num`     | `__u32`    | TCP sequence number.                          |
| `ack_num`     | `__u32`    | TCP acknowledgment number.                    |
| `tcp_flags`   | `__u8`     | TCP flags (FIN, SYN, RST, PSH, ACK, URG).     |


## <a name="bpf-maps-and-arrays"></a>3. BPF Maps and Arrays

### <a name="packet_count"></a>packet_count

A `BPF_HASH` map that stores the count of packets for each source IP address.  It uses the source IP address (`__u32`) as the key and a 64-bit unsigned integer (`__u64`) as the value (packet count). The map is sized to hold up to 1024 unique keys.

### <a name="sample_counter"></a>sample_counter

A `BPF_PERCPU_ARRAY` that acts as a per-CPU sampling counter. It has a single entry (`__u64`) to ensure atomic increment operations without race conditions across multiple CPUs.

## <a name="bpf-perf-buffer"></a>4. BPF Perf Buffer

### <a name="packet_events"></a>packet_events

A `BPF_PERF_OUTPUT` structure used to send detailed packet information (`struct packet_info`) to userspace for further processing and analysis.

## <a name="core-function-count_tcp_packets"></a>5. Core Function: count_tcp_packets

The `count_tcp_packets` function is the core of the eBPF program. It's triggered for each packet received.

### <a name="packet-processing-pipeline"></a>Packet Processing Pipeline

1. **Data Pointers:**  The function retrieves pointers to the beginning and end of the packet data from the `xdp_md` context.