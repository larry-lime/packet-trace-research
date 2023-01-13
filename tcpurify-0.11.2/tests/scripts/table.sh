#!/bin/sh

source $TCPURIFY_SCRIPTS/functions

FINAL=0

echo "table:"

# First check repeatability

echo -n "  repeatability..."
try $tcpurify -f $1 -o table-repeat-1.dmp table mapfile=map-repeat $2
try $tcpurify -f $1 -o table-repeat-2.dmp table mapfile=map-repeat

cmp -s table-repeat-1.dmp table-repeat-2.dmp
if test $? -ne 0; then
  echo " failed"
  FINAL=1
else
  rm -f table-repeat-1.dmp table-repeat-2.dmp map-repeat
  echo " OK"
fi

# Check that two subsequent runs get different results -- note that this
# could fail and not mean anything is wrong.  :-(

echo -n "  uniqueness..."
try $tcpurify -f $1 -o table-unique-1.dmp table mapfile=map-unique-1 $2
sleep 1
try $tcpurify -f $1 -o table-unique-2.dmp table mapfile=map-unique-2 $2

cmp -s table-unique-1.dmp table-unique-2.dmp
if test $? -eq 0; then
  echo " failed"
  FINAL=1
else
  rm -f table-unique-{1,2}.dmp map-unique-{1,2}
  echo " OK"
fi

# Check that -r works

echo -n "  reversibility..."
try $tcpurify -f $1 -o table-reverse-reference.dmp none
try $tcpurify -f $1 -o table-reverse-1.dmp table mapfile=map-reverse $2
try $tcpurify -r -f table-reverse-1.dmp -o table-reverse-2.dmp table mapfile=map-reverse

cmp -s table-reverse-reference.dmp table-reverse-2.dmp
if test $? -ne 0; then
  echo " failed"
  FINAL=2
else
  rm -f table-reverse-{reference,1,2}.dmp map-reverse
  echo " OK"
fi

exit $FINAL
