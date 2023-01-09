# Tcpdpriv Notes

This installation 

## Installation
### Install `libpcap`
1. `configure` requirements
    ```shell
    sudo apt install flex bison
    ```
2. Install `libpcap` library using apt
    ```shell
    sudo apt-get install libpcap-dev
    ```
    OR

    Install from [libpcap](https://github.com/the-tcpdump-group/libpcap) from source (but this doesn't seem to work)
### Install `tcpdpriv`
1. Install Requirements
    ```shell
    sudo apt install net-tools
    ```
2. Clone Gihub Repo. Following directions [here](https://fly.isti.cnr.it/software/tcpdpriv/)
3. Create a `VERSION` file and add the current `tcpdpriv` version
    ```shell
    touch VERSION && echo "1.1.11" >> VERSION
    ```
4. Make the following edits to `configure`

    Change line 9 to
    ```shell
    if gcc -v >& /dev/null; then
    ```
5. Make the following edits to `tcpdpriv.c`
    Change line 1504 to
    ```c
    static void usage(char *cmd);
    static void
    verify_and_print_args(char *cmd)
    {
    ```
## Usage
...
