# Packet Trace Anonymizer Table

## Anonymization Field Comparison Table

## TCPdpriv Anonymization Policy

| Changed Fields    | Change Approach                                                         | Use Cases |
| ----------------- | ----------------------------------------------------------------------- | --------- |
| IP Address        | [IP Address Change Approach](#ip-address)                               |
| IP Classness      | [IP Classness Change Approach](#ip-classness)                           |
| Multicast Address | [Multicast Address Mapping Change Approach](#multicast-address-mapping) |
| IP & TCP Options  | [IP & TCP Options Change Approach](#ip--tcp-options)                    |
| TCP Port Mapping  | [TCP Port Mapping Change Approach](#tcp-port-mapping)                   |
| UDP Port Mapping  | [UDP Port Mapping Change Approach](#udp-port-mapping)                   |

### Change Approach Extended

#### IP Address

- Level 0: Maps different addresses to integers (counting from 1)
- Level 1: Maps the upper and lower 16 bits, separately, to integers (counting from 1)
- Level 2: Maps each byte of the address separately (again, counting from 1) with each byte map independent
- Level 50: ...
- Level 99:

#### IP Classness

- Level 0: no class information is carried through
- Level 1: Class A addresses are mapped to Class A addresses
- Level 2: Additionally, Class B addresses are mapped to Class B addresses
- Level 3: Additionally, Class C addresses are mapped to Class C addresses
- Level 4: Additionally, Class D (mulitcast) addresses are mapped to Class D addresses

#### Multicast Address Mapping

- Level 0: Implies map using -A and -C values
- Level 10: Passes multicast addresses in globally-scoped datagrams through unchanged
- Level 20: Passes multicast addresses in continent-local datagrams through unchanged
- Level 70: Passes multicast addresses in site-local datagrams through unchanged
- Level 80: Passes multicast addresses in link-local datagrams through unchanged
- Level 90: Passes multicast addresses in node-local datagrams through unchanged

#### IP & TCP Options

- Level 0: Map 16-bit port numbers to a single integer
- Level 1: Maps each 8-bit byte in the same port number to a single integer
- Level 99: Passes port numbers through unchanged

#### TCP Port Mapping

- Set mappings for only tcp port numbers
- Same usage as -P

#### UDP Port Mapping

- Set mappings for only udp port numbers
- Same usage as -P

### Use Cases Extended

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

| Changed Fields       | Change Approach                                                       | Use Cases                                                               |
| -------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| IP Address (none)    | does nothing                                                          | default behavior                                                        |
| IP Address (nullify) | changes addresses to 0.0.0.0                                          | default anonymization behavior                                          |
| IP Address (table)   | [pseudo-randomizes IP addresses](#ip-address-table---change-approach) | [maintain uniquness, reconstructability](#ip-address-table---use-cases) |

### Change Approach Extended

#### IP Address (table) - Change Approach

- Randomizes the host bits of the IP address
- Uses the network mask to determine which bits belong to network, host, and subnet
- Creates a map file that can be used to restore the original host address
- Anonymization Algorithm:
  - `shuffle()` function accomplishes the anonymization
  - Uses `srand()` function to seed the pseudo-random number generator with current time
  - The bits from 1 to size -2 are shuffled three times
  - A new position is calculated using `rand()`
  - The corresponding bits are then swapped using the `swap` function accessing the table

### Use Cases Extended

#### IP Address (table) - Use Cases

- Provide a way to pseudo-randomly anonymize IP addresses while still maintaining their uniqueness
- Obviously if the IP address bits were purely randomly anonymized without retaining uniqueness, that would remain all research value from the packet captures. It would be the same as setting all bits to zero
- The IP addresses are encoded into a table that randomizes the bits, obfuscating the host address, while still allowing for consistent mapping between IP addresses and their encoded values
- In this way, the anonymized trace can be restored using the map file by the user executing tcpurify
  - This is useful in case security auditing demands that you restore the original IP address for analysis
  - At the same time, This allows for statistical analysis to be performed on network traffic data while maintaining privacy and anonymity for the users whose traffic is being analyzed.
