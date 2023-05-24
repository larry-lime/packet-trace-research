# Packet Trace Anonymizer Table

## Anonymization Field Comparison Table

## TCPdpriv Anonymization Policy

| Changed Fields    | Change Approach                                                         | Use Cases                                                                   |
| ----------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| IP Address        | [IP Address Change Approach](#ip-address)                               | [IP Address Use Cases](#ip-address-use-cases)                               |
| IP Classness      | [IP Classness Change Approach](#ip-classness)                           | [IP Classness Use Cases](#ip-classness-use-cases)                           |
| Multicast Address | [Multicast Address Mapping Change Approach](#multicast-address-mapping) | [Multicast Address Mapping Use Cases](#multicast-address-mapping-use-cases) |
| IP & TCP Options  | [IP & TCP Options Change Approach](#ip--tcp-options)                    | [IP & TCP Options Use Cases](#ip--tcp-options-use-cases)                    |

### Change Approach Extended

#### IP Address (-A)

- Level 0: Maps different addresses to integers (counting from 1)
- Level 1: Maps the upper and lower 16 bits, separately, to integers (counting from 1)
- Level 2: Maps each byte of the address separately (again, counting from 1) with each byte map independent
- Level 50: ...
- Level 99: ...

#### IP Classness (-C)

- Level 0: no class information is carried through
- Level 1: Class A addresses are mapped to Class A addresses
- Level 2: Additionally, Class B addresses are mapped to Class B addresses
- Level 3: Additionally, Class C addresses are mapped to Class C addresses
- Level 4: Additionally, Class D (mulitcast) addresses are mapped to Class D addresses

#### Multicast Address Mapping (-M)

- Level 0: Implies map using -A and -C values
- Level 10: Passes multicast addresses in globally-scoped datagrams through unchanged
- Level 20: Passes multicast addresses in continent-local datagrams through unchanged
- Level 70: Passes multicast addresses in site-local datagrams through unchanged
- Level 80: Passes multicast addresses in link-local datagrams through unchanged
- Level 90: Passes multicast addresses in node-local datagrams through unchanged

#### TCP & UDP Port Mapping (-P)

- Level 0: Maps 16-bit port numbers to a single integer
- Level 1: Maps each 8-bit byte in the same port number to a single integer

#### IP & TCP Options (-S)

- Level 0: Map 16-bit port numbers to a single integer
- Level 1: Maps each 8-bit byte in the same port number to a single integer
- Level 99: Passes port numbers through unchanged

### Use Cases Extended

#### IP Address Use Cases

The IP address mapping involves converting IP addresses into integers or manipulating different parts of the address independently. This provides a way to obfuscate the original IP addresses while still preserving certain properties or relationships for analysis purposes.

The range of levels from 0 to 99 can be seen as a continuum of trade-offs between privacy and utility.

For example, Level 0 maps all the bits in the address to a single integer, and 99 passes the address as is. Intermediate levels of mapping allow for more granular control.

#### IP Classness Use Cases

IP Classness (Levels 0-4): This feature allows preserving the class information of IP addresses during mapping. It can be useful when analyzing network traffic based on different IP address classes, such as Class A, Class B, Class C, or multicast addresses. By maintaining the class information, the anonymized traces can still provide insights into the distribution and behavior of different IP address classes.

#### Multicast Address Mapping Use Cases

Multicast Address Mapping (Levels 0-90): Multicast addresses are handled separately to ensure appropriate treatment based on the scope of the address. Different levels of mapping determine whether multicast addresses are changed or left unchanged based on their scope, such as globally-scoped, continent-local, site-local, link-local, or node-local datagrams. This enables the anonymization of multicast traffic while maintaining the necessary distinctions for analysis.

#### TCP & UDP Port Mapping Use Cases

TCP Port Mapping: This component specifically focuses on mapping TCP port numbers. It provides a way to anonymize TCP traffic while preserving certain mappings for specific port numbers. This can be useful when analyzing network activities based on different services or applications using distinct port numbers.

UDP Port Mapping: Similar to TCP port mapping, this component focuses on anonymizing UDP port numbers while maintaining specific mappings for certain port numbers. UDP-based services or applications can be anonymized while still preserving the relationships between port numbers.

#### IP & TCP Options Use Cases

IP & TCP Options: This feature involves mapping IP and TCP options within the packet headers. Different levels of mapping determine the granularity at which the options are anonymized. For example, at Level 0, port numbers are mapped to a single integer, which can be useful for statistical analysis of port usage. Higher levels allow preserving more information by mapping each byte or passing the port numbers through unchanged (Level 99).

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
