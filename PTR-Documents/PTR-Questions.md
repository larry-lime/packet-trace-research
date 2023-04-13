# Packet Trace Research - Questions

## General Project Questions

- Is the "Change Approach" field in comparison table is the same thing as anon policy?

## TCPdpriv

## TCPmkpub

- Why am I not able to use two networks of the same IP network in `topology.anon`

## TCPurify

- From this [tcpurify webpage](https://isc.sans.edu/diary/Truncating+Payloads+and+Anonymizing+PCAP+files/23990):
  - "Those filters are save in a map file to be able to reconstruct the original PCAL if required later."
  - Is this a typo? Should it be "PCAP" instead of "PCAL"?
- "This will randomize IP addresses from 192.168.0.0/16 except the network & broadcast addresses (example: '192.168.1.2' will be anonymized to '192.168.123.43')"
  - I don't quite understand this just yet

## Wireshark

- Are you able to get IP subnet from wireshark packet capture?
  - Yes. Just calculate the subnet based on

## General Computer Networking

- Can you determine the subnet mask of a network from a packet trace
