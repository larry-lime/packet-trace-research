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

#### Resources

#### Anonymization Policy

##### Important flags to keep in mind:

- -A: IP Address
  - Level 0: Maps different addresses to integers (counting from 1)
  - Level 1: Maps the upper and lower 16 bits, separately, to integers (counting from 1)
  - Level 2: Maps each byte of the address separately (again, counting from 1) with each byte map independent
  - Level 50: ...
  - Level 99:
- -C: Classness of IP
  - Level 0: no class information is carried through
  - Level 1: Class A addresses are mapped to Class A addresses
  - Level 2: Additionally, Class B addresses are mapped to Class B addresses
  - Level 3: Additionally, Class C addresses are mapped to Class C addresses
  - Level 4: Additionally, Class D (mulitcast) addresses are mapped to Class D addresses
- -M: Multicast address mapping
  - Level 0: Implies map using -A and -C values
  - Level 10: Passes multicast addresses in globally-scoped datagrams through unchanged
  - Level 20: Passes multicast addresses in continent-local datagrams through unchanged
  - Level 70: Passes multicast addresses in site-local datagrams through unchanged
  - Level 80: Passes multicast addresses in link-local datagrams through unchanged
  - Level 90: Passes multicast addresses in node-local datagrams through unchanged
- -P: TCP & UDP port number mapping
  - Level 0: Map 16-bit port numbers to a single integer
  - Level 1: Maps each 8-bit byte in the same port number to a single integer
  - Level 99: Passes port numbers through unchanged
- -S: IP & TCP options mapping
  - Level 0: Replaces all options with NOPs (0x01 in both cases)
  - Level 1: Leaves all the options unchanged
- -T: TCP port numbers mapping
  - Set mappings for only tcp port numbers
  - Same usage as -P
- -U: UDP port numbers mapping
  - Set mappings for only udp port numbers
  - Same usage as -P

##### Understanding the flags

- [x] Understand IP Address mapping
- [x] Understand Classness of IP mapping
- [ ] Understanding Multicast address mapping
  - [ ] What is multicast?
  - [ ] How is it mapped?
- [ ] Understanding TCP & UDP port number mapping
  - [ ] What is a port number?
  - [ ] How is it mapped?

Additional traits of tcpdpriv

- When the header is changed, the checksum for that header is also updated to reflect the changed header data values

#### Function Explanation

#### Tool Overview

- The tcpdpriv creator provides their "Thoughts on How to Mount an Attack on tcpdpriv's ``-A50'' Option..."
- Something noteable is that, tcpdpriv removes sensitive information from a packet trace, replacing it with contrived information. And (unlike tcpurify) the sensitive information CANNOT be reconstructed from the sensitive information
- Unlike tcpurify, tcpdpriv provies many options for different levels of privacy/security. Generally, the smaller the number, the more secure
  - The number (0) is the default for each of the options and is the most secure
  - The number (99) generally means "release the information as is"

#### Missing Options

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

#### Function Explanation

- The actual randomization of the IP addresses is done in this `shuffle()` function.

  ```c
  /*
   * If you don't recognize this, you shouldn't be reading this source.  ;-)
   */
  static void swap (uint32_t *table, uint32_t x, uint32_t y) {
    uint32_t temp;

    temp = table[x];
    table[x] = table[y];
    table[y] = temp;
  }

  /*
   * A simple randomization function that shuffles entries 1 .. size - 2
   * of the given table.  It leaves the first and last entries for the reasons
   * discussed in the accompanying README file.
   */
  static void shuffle (uint32_t *table, uint32_t size) {
    uint32_t i, j, newpos;

    srand (time (NULL));
    for (i = 0; i < 3; i++) {
      for (j = 1; j < size - 1; j++) {
        newpos = 1 + (int)((double)(size - 2) * rand() / (RAND_MAX + 1.0));
        swap (table, j, newpos);
      }
    }
  }
  ```

- Almost all of the "interesting" anonymization happens in the `encode_table.c` file.
- There is also the `encode_none.c` and `encode_nullify.c` files that are used to handle the `none` and `nullify` options respectively.
- Within the `encode_table.c` file, I'd say, the important functions to keep in mind are the following:
  - `table_write()` and `table_read()`- These are the functions that are used to write and read the table to and from a file
  - `shuffle()` - This is the function that actually randomizes the IP addresses. It's called from within `table_create()`
  - `table_create()` - This takes a properly filled-out Network structure and creates a random table in network->table for address translation.
  - `squish()` and `unsquish()`- Are the functions that are used to compress and decompress IP addresses in the table. Its interesting

#### Tool Overview

- Very light tcpdump clone
- Does not allow fine tuning the capture session
- Three main ways of using
  - none
  - nullify
  - table
- 'Table' mode requires an extra argument, 'mapfile' which points to a filename that will contain the mappings
- Something of note: If a map file is specified and no triplets (subnet/netmask/xformmask) are specified in the command line, tpurify will read the map file and initialize the mapping table
  - Does this mean that you can reuse the same map file for multiple anonymizations?

#### Missing Options

- No support for BPF filters
  - What this means is that you can't restrict traffic when reading from a network interface
