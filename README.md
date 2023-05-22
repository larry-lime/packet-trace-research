# Packet Trace Research Notes

This installation has been tested on Ubuntu 20.04 LTS for x64 operating systems

## `tcpdpriv` Installation

### Requirements

1. Install `configure` requirements
   ```shell
   sudo apt install flex bison
   ```
1. Install `libpcap` library using apt
   ```shell
   sudo apt-get install libpcap-dev
   ```

### Build tcpdpriv

1. Install Requirements

   ```shell
   sudo apt install net-tools
   ```

1. If you're building from the files in this repo, skip to Step 6.

   Otherwise, unzip the tar file found [here](https://fly.isti.cnr.it/software/tcpdpriv/)

1. Create a `VERSION` file and add the current `tcpdpriv` version

   ```shell
   echo "1.1.11" > VERSION
   ```

1. Make the following edits to `configure`

   Line 9:

   ```shell
   if gcc -v > /dev/null; then
       ...
   ```

1. Make the following edits to `tcpdpriv.c`
   Line 1504

   ```c
   static void usage(char *cmd);
   static void
   verify_and_print_args(char *cmd)
       ...
   {
   ```

1. Run `make`

## Usage

Running `sudo ./tcpdpriv` in the `tcpdpriv` build directory should produce the following output:

```shell
$ sudo ./tcpdpriv
[sudo] password for user:
attempt to write binary dump file to tty
usage:
./tcpdpriv [-Opq] [-a [[hh:]mm:]ss] [-A {0|1|2|50|99}] [-c count]
                [-C {0|1|2|3|4|...|32|99}] [-F file] [-i interface]
                [-M {0|10|20|70|80|90|99}] [-{P|T|U} {0|1|99}] [-r file]
                [-s snaplen] [-w outputfile] [expression]
(one reasonable choice:  ./tcpdpriv -P99 -C4 -M20 ...)
```

## `tcpmkpub` Installation

1. Follow the directions in `INSTALL` until step 2
   - For ARM based systems execute this configure command
   ```shell
   ./configure --build=aarch64-unknown-linux-gnu
   ```
1. Add the following imports to the top of `A50.cc`
   ```cpp
   #include <cassert>
   ```
1. Add the following imports to the top of`Packet.cc`
   ```cpp
   #include <cstring>
   ```
1. Add the following imports to the top of`Special.h`
   ```cpp
   #include <cstring>
   ```
1. Make the following changes to `Scanner.cc` on line 64
   ```cpp
   bool DetectSequentialScan(bool ascending);
   ```
1. Add the following imports to the top of`Scanner.cc`
   ```cpp
   #include <cstring>
   ```
1. Run `make` and `make install`
1. Optional 8th step: If you're pushing to this repo, make sure you're running `make clean && make distclean` to delete binaries and generated config files in the build directory

## Usage

Running the global command `tcpmkpub` should produce the following output:

```shell
$ tcpmkpub
Error: a key must be specified with '-k'
Usage: tcpmkpub [-DSTW] [-f <pcap filter>] [-k <key>] [-K] [-w <output file>] [-s <output scanner file>] <input files...>
...
```

## Sample Traces Folder

- 200722_win_scale_examples_anon.pcapng: TCP Window Scaling examples - available, no scaling and missing/unknown.
- 200722_tcp_anon.pcapng Netcat - string, file and characters.
