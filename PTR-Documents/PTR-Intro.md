## Build Packet Anonymizers

## Netcat

### Resources

[What is Netcat](https://www.geeksforgeeks.org/introduction-to-netcat/)

### Notes

Netcat uses TCP and UDP connections to read and write to a network

- Netcat's terminal command is `nc`
  Here are some of the things you can do with Netcat
- Connect to a server
- Chatting between two users
- File transfer

## Wireshark

### Resources

- Use Packet Anonymization tools on [Wireshark Samples Captures](https://wiki.wireshark.org/SampleCaptures)
- UMass Labs
  - [Getting Started](http://www-net.cs.umass.edu/wireshark-labs/Wireshark_Intro_v8.0.pdf)
  - [HTTP](http://www-net.cs.umass.edu/wireshark-labs/Wireshark_HTTP_v8.0.pdf)
  - [DNS](http://www-net.cs.umass.edu/wireshark-labs/Wireshark_DNS_v8.0.pdf)
  - [TCP](http://www-net.cs.umass.edu/wireshark-labs/Wireshark_TCP_v8.0.pdf)

### Tasks

- [X] Complete Getting Started
- [X] Complete HTTP Lab
- [ ] Complete DNS Lab
- Look into section 2.4 of the textbook for more information
- [ ] Complete TCP Lab

### Notes

- Fundamentally understand the difference between HTTP, DNS, and TCP
- Get IP
  - `hostname -I`
- Flush DNS cache on linux
  - Install `nscd` with apt
  - run `sudo /etc/init.d/nscd restart`

### Meeting Notes

`tcpmkpub`

- IP layter
  The packet
- Byte string
- Represents the packet
  HTTP
  DNS
  TCP

Support different types of fields
They anonymize in a different way
Identify the different ways in which the tools anonymize the packets and how do they do it
