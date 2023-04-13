# Packet Trace Research - Notes

## General Computer Networking Notes

### IP Address Information

#### Classes of IP Addresses

| Class | First Octet Value | Subnet Mask |
| ----- | ----------------- | ----------- |
| A     | 0-127             | 8           |
| B     | 128-191           | 16          |
| C     | 192-223           | 24          |

#### IP Fragmentation

[IP Fragmentation Wikipedia](https://www.google.com/search?channel=fs&client=ubuntu-sn&q=what+is+ip+frag)

#### IP Subnets

[Subnetting & Subnet Masks Explained](http://www.steves-internet-guide.com/subnetting-subnet-masks-explained/)
[What is a subnet? | How subnetting works](https://www.cloudflare.com/learning/network-layer/what-is-a-subnet/)

### ICMP Information

- [ICP Wikipedia](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
- [ICMP Router Discovery Protocol](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwinu56Lipr-AhVUAYgKHaGhCKkQFnoECA4QAw&url=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FICMP_Router_Discovery_Protocol&usg=AOvVaw2KK53UwOj7X19UXXdPvtto)
- [ICMP Parameter Problem](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwjv1O2_ipr-AhXWA94KHUJWBC0QFnoECA0QAw&url=https%3A%2F%2Fwww.omnisecu.com%2Ftcpip%2Ficmp-parameter-problem-messages.php&usg=AOvVaw0arujt2_WN6hUl5GF2bw7x)

### TCPdump Notes

#### Resources

- [TCPdump Wiki](https://en.wikipedia.org/wiki/Tcpdump)

#### Tool Overview

TCPdump is a packet analyzer which sniffs and prints the contents of network packets. It can sniff packets either from a network interface card (on your device) or a previously saved packet file. It also prints the output

You are also able to use tcpdump to intercept and displays the communication of another user or computer. You can act as a router or a gateway to view login IDs, passwords, and URLs of websites being viewed from various devices. This must be encrypted though.

## Packet Anonymizer Tools Notes

### TCPdpriv

#### Anonymization Policy

Important flags to keep in mind:

- -A: IP Address
- -C: Classness of IP
- -M: Multicast address mapping
- -P: TCP & UDP port number mapping
- -S: IP & TCP options mapping
- -T: TCP port numbers mapping
- -U: UDP port numbers mapping

### TCPmkpub

#### Enterprise networks

- When we anonymize the packets, we have to figure out whether we need to be putting the source IP, i.e. the tcp source in the capture file as the ENTERPRISE_NETWORK in `topology.anon` or our actual current IP.
- I imagine that if we are capturing and anonymizing packets from our current IP, we'll use the latter. Otherwise, we should use the other method

##### Using the IP of the packet trace

Packets anonymized using this method will be named with `v1` in the name. For example, `netcat_tcpmkpub_v1_anon.pcapng`

**Observations:**

Using more than one `ENTERPRISE_NETWORK` throws an error
This does not work:

```
ENTERPRISE_NETWORK("192.168.200.135/24", "dev_one")
ENTERPRISE_NETWORK("192.168.200.21/24", "dev_two")
...
ENTERPRISE_SUBNET("192.168.200.135", "255.255.255.0", "", "", PRESERVE, "")
ENTERPRISE_SUBNET("192.168.200.21", "255.255.255.0", "", "", PRESERVE, "")
```

You must remove the second enterprise network and subnet for it to work properly. Like so:

```
ENTERPRISE_NETWORK("192.168.200.135/24", "dev_one")
...
ENTERPRISE_SUBNET("192.168.200.135", "255.255.255.0", "", "", PRESERVE, "")
```

There are also alerts about 'bad TCP checksum'. I don't quite know what that's about. This is there all the time

##### Using my actual current IP address

Packets anonymized using this method will be named with `v2` in the name. For example, `netcat_tcpmkpub_v1_anon.pcapng`

I'm using my current IP address as shown from running the `ifconfig` command. I'm calling it starbucks because I'm starbucks. The name doesn't matter.

```
ENTERPRISE_NETWORK("192.168.64.9/24", "starbucks")
...
ENTERPRISE_SUBNET("192.168.64.9", "255.255.255.0", "", "", PRESERVE, "")
```

There are also alerts about 'bad TCP checksum' here. Previous question still stands

##### Using an arbitrary IP address

Packets anonymized using this method will be named with `v3` in the name. For example, `netcat_tcpmkpub_v1_anon.pcapng`

IP address used: 129.144.50.56. Sample IP from [Oracle IP Instructional](https://docs.oracle.com/cd/E19504-01/802-5753/planning3-18471/index.html)

The output anonymized pcap file is the same as if using our actual IP address. This was easy enough to predict. You can verify this with an md5 hash

### TCPurify

#### Resources

- [Truncating Payloads and Anonymizing PCAP files](https://isc.sans.edu/diary/Truncating+Payloads+and+Anonymizing+PCAP+files/23990)
- [Berkely Packet Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)

#### Anonymization Policy

- Rationale:
  - Secure alternative to tcpdump
  - Create dump files with IP addresses obfuscated in a way such that the original traffic data is impossible to reconstruct
- Three different methods:
  - none: does nothing
  - nullify: replaces all IP addresses with 0.0.0.0
  - table
- Table method:
  - Define subnets to be anonymized using filters
  - Filters are then saved to a map file to be able to reconstruct the original PCAP file if required
  - How to define a filter:
    - subnet/netmask/xformmask
    -
  - Example:
    - 192.168.0.0/0xffff0000/0xffff

#### Copilot Labs Explaination

Explain the following `encode_table()` function in `encode_table.c`

```c
void encode_table (uint32_t *ip)
{
  int i;

  /* Squint real hard and it makes sense, I promise */
  for (i = 0; networks[i].subnet != 0; i++) {
    if (((*ip & networks[i].netmask) ^ networks[i].subnet) == 0) {
      *ip = ((*ip & ~networks[i].xformmask)
	     | (networks[i].table[ntohl(*ip & networks[i].xformmask)]));
    }
  }
}
```

1. The first for loop goes through each network in the networks[] array
   until it finds one whose subnet is 0. This is a sentinel value
   indicating the end of the array.
2. The if clause is the actual check for whether the ip address
   belongs to the network we are currently looking at. The
   networks[i].netmask is a mask with 1's in the bits that are
   significant to the subnet. The networks[i].subnet is the subnet
   address with the bits that are not significant to the subnet set to 0. The expression
   (\*ip & networks[i].netmask) ^ networks[i].subnet
   will give 0 if the ip address belongs to the subnet. The
   parentheses are needed to force the bitwise and to be performed
   first.
3. The else clause is a little more complex. If the ip address does
   not belong to the network we are currently looking at, we need to
   see if it belongs to any of the other networks. This is accomplished
   by the continue statement which causes the loop to go back to the
   top and look at the next network.
4. If the ip address does belong to the network, we need to do the
   transformation. The following lines
   *ip = ((*ip & ~networks[i].xformmask)
   | (networks[i].table[ntohl(\*ip & networks[i].xformmask)]));
   perform the transformation. The first part sets all the bits that
   are not significant to the subnet in the ip address to 0. The second
   part takes the bits that are significant to the subnet (those that
   were not set to 0 in the first part) and uses them as an index into
   the transformation table for the network.
5. The table is an array of 32 bit integers (uint32_t) indexed by the
   significant subnet bits. The table is created by the decode_table()
   function.
6. The ntohl() function converts from network byte order (big endian)
   to host byte order (little endian). The reason for this is that the
   transformation table is created by reading the ip addresses from a
   file. The file is in host byte order (because it was created on
   the host), but the ip addresses in the table are in network byte
   order so that they can be compared to the ip addresses in network
   byte order. (The ip addresses in the table are in network byte
   order, but when they are read from the file, they are in host byte
   order.) It is also possible to create the table by reading the
   ip addresses in network byte order, but that would be more complex
   and would require a separate program to create the table.

#### Tool Overview

- Very light tcpdump clone
- Does not allow fine tuning the capture session
- Three main ways of using
  - none
  - nullify
  - table
- 'Table' mode requires an extra argument, 'mapfile' which points to a filename that will contain the mappings

#### Missing Options

- No support for BPF filters
  - What this means is that you can't restrict traffic when reading from a network interface
