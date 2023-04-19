## Tool Status

| Tool Name | Built | Binary Executable | Tested with Packet Trace |
| --------- | ----- | ----------------- | ------------------------ |
| tcpdpriv  | ✅    | ✅                | ✅                       |
| tcpmkpub  | ✅    | ✅                | ✅                       |
| tcpurify  | ✅    | ✅                | ✅                       |

## SampleCaptures

- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures#sample-captures)
- Use [200722_tcp_anon.pcapng Netcat - string, file and characters.](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/200722_tcp_anon.pcapng) for testing
- Renamed to netcat_tcp_anon.pcapng

## TCPdpriv

### Build Binary

```shell
./configure
make
```

### Check Binary is executable

#### Command:

```shell
sudo ./tcpdpriv
```

#### Expected Ouput:

```
[sudo] password for larrylime:
attempt to write binary dump file to tty
usage:
./tcpdpriv [-Opq] [-a [[hh:]mm:]ss] [-A {0|1|2|50|99}] [-c count]
                [-C {0|1|2|3|4|...|32|99}] [-F file] [-i interface]
                [-M {0|10|20|70|80|90|99}] [-{P|T|U} {0|1|99}] [-r file]
                [-s snaplen] [-w outputfile] [expression]
(one reasonable choice:  ./tcpdpriv -P99 -C4 -M20 ...)
```

### Anonymize Sample Packet

Command:

```shell
sudo ./tcpdpriv -P99 -C4 -M20 -w <path-to-output-*.pcapng> -r <path-to-input-*.pcapng>
```

Expected Output:

```
# map 32-bit addresses into sequential integers
# multicast addressses in datagrams scoped continent-local
#       (33 <= ttl <= 128) passed through unchanged
# multicast addressses in datagrams scoped global
#       (129 <= ttl <= 255) passed through unchanged
# pass TCP port numbers through unchanged
# pass UDP port numbers through unchanged
# pktsin 35 pktsout 35 tooshort 0 uncoded 0
```

## TCPmkpub

### Set Enterprise Network

1. Get current ip address
   ```shell
   curl ifconfig.me
   ```

### Build Binary

```shell
./configure --build=arm-linux
make
make install
make clean && make distclean # To remove output files
```

### Check Binary is executable

#### Command

```shell
tcpmkpub
```

#### Expected Output

```
Error: a key must be specified with '-k'
Usage: tcpmkpub [-DSTW] [-f <pcap filter>] [-k <key>] [-K] [-w <output file>] [-s <output scanner file>] <input files...>
Options:

-D
Debug mode.

-S
Speculative mode. Ordinarily the traces will be read twice, with the first pass to collect data for generating IP address mapping. In speculative mode, the input will only be read once, and there is a (small) chance that mapping conflicts occur. The speculative mode is useful for reading traces from the standard input.
...
```

### Configure Enterprise Network

1. Go to `topology.anon`

TODO: RETURN HERE

### Anonymize Sample Packet

1. Create file with 32 character anonymization key

   ```
   echo "00000000000000000000000000000000" > .tcpmkpub-key
   ```

2. Run `tcpmkpub` with the correct md5 digest
   ```shell
   tcpmkpub -k cd9e459ea708a948d5c2f5a6ca8838cf -w <path-to-output.*.pcapng> <path-to-input-*.pcapng>
   ```

## TCPurify

### Build Binary

```shell
./configure --build=arm-linux
make
make install
make clean && make distclean # To remove output files
```

### Check Binary is executable

#### Command

```shell
tcpmkpub
```

#### Expected Output

```
Usage: tcpurify [OPTIONS] <encoding> [ENCODING OPTIONS]
Where options consist of:
  -d            debug
  -x            disable IP packet truncation
  -R            reverse previous mapping (requires -m)
  -t            output packets from a dump file as if in real time
  -i interface  read input from device interface
  -f filename   -or-
  -r filename   read input from file filename
  -o filename   -or-
  -w filename   send output to file filename
  -c count      capture only count packets
  -T time       Maximum time between real-time packets
  -V            verify the TCP checksum and store success code in its place
  -h            display this message and exit
  -v            display version information and exit

 Current valid values for <encoding> are:
  none          No IP address transformation will be performed
  table         Simple table-based transformation
```

### Anonymize Sample Packet

Command:

#### `none` encoding

Produces an output file with IP addresses and all other fields unchanged

```shell
tcpurify -r <path-to-input-*.pcapng> -w <path-to-output.*.pcapng>  none
```

#### `nullify` encoding

Produces an output file with all source and destination IP addresses changed to 0.0.0.0.

```shell
tcpurify -r <path-to-input-*.pcapng> -w <path-to-output.*.pcapng>  nullify
```

#### `table` encoding

Specifies a range of subnets to obfuscate along with the bits you wish to randomize.

```shell
tcpurify -r <path-to-input-*.pcapng> -w <path-to-output>*.pcapng> table 192.168.200.0/0xffffff00/0xff mapfile=test.map
```

Example usage:

```shell
tcpurify -r <path-to-input-*.pcapng> -w <path-to-output>*.pcapng> table subnet/netmask/xformmask mapfile=<filename.map>
```
