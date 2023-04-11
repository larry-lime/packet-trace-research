# Packet Trace Anonymizer Table

## Anonymization Field Comparison Table

## TCPdpriv Anonymization Policy

| Changed Fields    | Change Approach | Use Cases |
| ----------------- | --------------- | --------- |
| IP Address        |                 |           |
| IP Classness      |                 |           |
| Multicast Address |                 |           |
| IP Options        |                 |           |
| TCP Options       |                 |           |
| TCP Port Mapping  |                 |           |
| UDP Port Mapping  |                 |           |

The following is in order in which they appear in the fields of the tool

IP

- IP Address
- IP Classness
- Multicast Address Mapping
- IP Options
- TCP Options
- TCP & UDP Port Mapping (together)
- TCP Port Mapping
- UDP Port Mapping

## TCPmkpub Anonymization Policy

| Changed Fields                           | Change Approach | Use Cases |
| ---------------------------------------- | --------------- | --------- |
| Ethernet Address                         |                 |           |
| Ethernet Data                            |                 |           |
| Address Resolution Protocol ARP          |                 |           |
| IP Address                               |                 |           |
| IP Fragmentation                         |                 |           |
| IP Options                               |                 |           |
| IP Data                                  |                 |           |
| Internet Control Message Protocol (ICMP) |                 |           |
| ICMP Data                                |                 |           |
| ICMP Echo                                |                 |           |
| ICMP Context                             |                 |           |
| ICMP Redirect                            |                 |           |
| ICMP Routers                             |                 |           |
| ICMP Router Solicitation                 |                 |           |
| ICMP Parameter Problem                   |                 |           |
| ICMP Timestamp                           |                 |           |
| ICMP Information Request                 |                 |           |
| ICMP Mask Request                        |                 |           |
| UDP                                      |                 |           |
| TCP                                      |                 |           |
| TCP Options                              |                 |           |

The following is in order in which they appear in the fields of the table in the paper

Ethernet

- Ethernet Address
- Ethernet Data
- Address Resolution Protocol ARP

IP

- IP Address
- IP Fragmentation
- IP Options
- IP Data

ICMP

- Internet Control Message Protocol (ICMP)
- ICMP Data
- ICMP Echo
- ICMP Context
- ICMP Redirect
- ICMP Routers
- ICMP Router Solicitation
- ICMP Parameter Problem
- ICMP Timestamp
- ICMP Information Request
- ICMP Mask Request

TCP & UDP

- UDP
- TCP
- TCP Options

## TCPurify

| Changed Fields       | Change Approach                        | Use Cases            |
| -------------------- | -------------------------------------- | -------------------- |
| IP Address (none)    | does nothing                           | default behavior     |
| IP Address (nullify) | replaces all IP addresses with 0.0.0.0 | no apparent use case |
| IP Address (table)   | randomizes subnet IP addresses         |                      |

- Three different methods:
  - none: does nothing
  - nullify: replaces all IP addresses with 0.0.0.0
  - table
- Table method:
  - Define subnets to be anonymized using filters
  - Filters are then saved to a map file to be able to reconstruct the original PCAP file if required
  - How to define a filter:
    - subnet/netmask/xformmask
  - Example:
    - 192.168.0.0/0xffff0000/0xffff
