# Packet Anonymizer Notes

## IP Address Information

### Classes of IP Addresses

| Class | First Octet Value | Subnet Mask |
| ----- | ----------------- | ----------- |
| A     | 0-127             | 8           |
| B     | 128-191           | 16          |
| C     | 192-223           | 24          |

## TCPdpriv

### Anonymization Policy

Important flags to keep in mind:

- -A: IP Address
- -C: Classness of IP
- -M: Multicast address mapping
- -P: TCP & UDP port number mapping
- -S: IP & TCP options mapping
- -T: TCP port numbers mapping
- -U: UDP port numbers mapping

## TCPmkpub

### Enterprise networks

- When we anonymize the packets, we have to figure out whether we need to be putting the source IP, i.e. the tcp source in the capture file as the ENTERPRISE_NETWORK in `topology.anon` or our actual current IP.
- I imagine that if we are capturing and anonymizing packets from our current IP, we'll use the latter. Otherwise, we should use the other method

#### Using the IP of the packet trace

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

#### Using my actual current IP address

Packets anonymized using this method will be named with `v2` in the name. For example, `netcat_tcpmkpub_v1_anon.pcapng`

I'm using my current IP address as shown from running the `ifconfig` command. I'm calling it starbucks because I'm starbucks. The name doesn't matter.

```
ENTERPRISE_NETWORK("192.168.64.9/24", "starbucks")
...
ENTERPRISE_SUBNET("192.168.64.9", "255.255.255.0", "", "", PRESERVE, "")
```

There are also alerts about 'bad TCP checksum' here. Previous question still stands

#### Using an arbitrary IP address

Packets anonymized using this method will be named with `v3` in the name. For example, `netcat_tcpmkpub_v1_anon.pcapng`

IP address used: 129.144.50.56. Sample IP from [Oracle IP Instructional](https://docs.oracle.com/cd/E19504-01/802-5753/planning3-18471/index.html)

The output anonymized pcap file is the same as if using our actual IP address. This was easy enough to predict. You can verify this with an md5 hash

## TCPurify
