/****************************************************************************
 * 
 * tcpurify - encode_nullify.c
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#include <inttypes.h>
#include <stdio.h>
#include "encode_nullify.h"

int encode_nullify_init (int argc, char *argv[])
{
  if (argc) {
    fprintf (stderr, "This encoding takes no arguments\n");
    return (1);
  }
  return (0);
}

void encode_nullify (uint32_t *ip)
{
  *ip = 0;
}

void encode_nullify_cleanup ()
{
}
