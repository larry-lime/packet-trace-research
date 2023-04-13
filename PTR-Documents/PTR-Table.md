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

| Changed Fields       | Change Approach                | Use Cases                      |
| -------------------- | ------------------------------ | ------------------------------ |
| IP Address (none)    | does nothing                   | default behavior               |
| IP Address (nullify) | changes addresses to 0.0.0.0   | default anonymization behavior |
| IP Address (table)   | randomizes subnet IP addresses |                                |
