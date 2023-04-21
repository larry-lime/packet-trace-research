# Packet Trace Research - Questions

## General Project Questions

- Is the "Change Approach" field in comparison table is the same thing as anon policy?

## TCPdpriv
- What is a NOP? (Ex. 0x01)

## TCPmkpub

- Why am I not able to use two networks of the same IP network in `topology.anon`

## TCPurify

- From this [tcpurify webpage](https://isc.sans.edu/diary/Truncating+Payloads+and+Anonymizing+PCAP+files/23990):
  - "Those filters are save in a map file to be able to reconstruct the original PCAL if required later."
  - Is this a typo? Should it be "PCAP" instead of "PCAL"?
- "This will randomize IP addresses from 192.168.0.0/16 except the network & broadcast addresses (example: '192.168.1.2' will be anonymized to '192.168.123.43')"
  - I don't quite understand this just yet
- Q: Given a pcap file, can you determine netmask?
  A: No, it is not possible to determine the netmask of a network just by analyzing a PCAP file. A PCAP file is simply a packet capture file that contains recorded network traffic, and it does not provide information about the network topology or subnetting.
  The netmask is a configuration parameter that is set on a network device, such as a router or a computer, to define the network address range of a particular subnet. It is used to determine which part of an IP address represents the network address and which part represents the host address.
  To determine the netmask of a network, you need to have access to the configuration of the network device that manages that network or obtain information from the network administrator.
- What is host byte order versus network byte order?
  - This is just the host address versus the network address
- What does the `htonl()` function do?
- Something of note: If a map file is specified and no triplets (subnet/netmask/xformmask) are specified in the command line, tpurify will read the map file and initialize the mapping table
  - Does this mean that you can reuse the same map file for multiple anonymizations?

## Wireshark

- Are you able to get IP subnet from wireshark packet capture?
  - Yes. Just calculate the subnet based on

## General Computer Networking

- Can you determine the subnet mask of a network from a packet trace
