#!/bin/sh

source $TCPURIFY_SCRIPTS/functions

# There's not a whole lot we can check with the none plugin; A simple
# sanity check is that two runs on the same file produce the same
# result, so that's what we'll do.  Verification of 'none' basically
# has to be done by hand, as that's what we'll be basing other checks
# on.

try $tcpurify -f $1 -o none-1.dmp none
try $tcpurify -f $1 -o none-2.dmp none

cmp -s none-1.dmp none-2.dmp
if test $? -ne 0; then
  echo "none test failed."
fi

rm -f none-1.dmp none-2.dmp
echo "none test succeeded."
