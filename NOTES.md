# Tcpdpriv Notes

## Changes to `configure`
1. Line 9:
  CHANGE
  ```shell
  if gcc -v >& /dev/null; then
  ```
  TO
  ```shell
  if gcc -v > /dev/null; then
  ```
2. Line 26
  Create a `VERSION` file in the `tcpdpriv` directory with the latest version (1.1.11)
  That way, this line won't throw an error
  ```shell
  VERSION="-e s/#__VERSION__#/`cat VERSION`/"
  ```
## Changes to `tcpdpriv.c`
1. Line 1504
  CHANGE
  ```c
  static void
  verify_and_print_args(char *cmd)
  {
      static void usage(char *cmd);
  ```
  TO
  ```c
  static void usage(char *cmd);
  static void
  verify_and_print_args(char *cmd)
  {
  ```
