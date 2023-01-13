/****************************************************************************
 * 
 * tcpurify - dump.c
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "tcpurify.h"

void dump_open()
{
  if(config.outfile == NULL) {
    config.outfile = "-";
  }

  if ((config.d = pcap_dump_open (config.p, config.outfile)) == NULL) {
    fprintf (stderr, "Error opening %s for output\n",
	     strcmp (config.outfile, "-") ? config.outfile : "stdout");
    exit (1);
  }
}

/* This makes lots of pretty errors when your disk gets full :-P */
void dump(const struct pcap_pkthdr *ph, const u_char *pkt)
{
  pcap_dump ((void *)config.d, ph, pkt);
}

void dump_close()
{
  pcap_dump_close (config.d);
}
