/****************************************************************************
 * 
 * tcpurify - encode_none.c
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#include <inttypes.h>
#include <stdio.h>
#include "encode_none.h"

int encode_none_init (int argc, char *argv[])
{
  if (argc) {
    fprintf (stderr, "This encoding takes no arguments\n");
    return (1);
  }
  return (0);
}

void encode_none (uint32_t *ip)
{
}

void encode_none_cleanup ()
{
}
