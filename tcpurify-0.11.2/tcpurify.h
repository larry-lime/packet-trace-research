/****************************************************************************
 * 
 * tcpurify - tcpurify.h
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#ifndef TCPURIFY_H
#define TCPURIFY_H

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <pcap.h>

#include "config.h"

#define PKT_LEN 144		/* This should be enough for any headers*/

struct Config {
  int debug;			/* debugging output on/off		*/
  int truncate;			/* truncate packets on/off		*/
  int reverse;			/* reverse mapping on/off		*/
  int timed;			/* real-time output on/off		*/
  uint32_t maxtime;		/* maximum time between realtime packets*/
  int verify_cs;		/* verify checksums			*/
  char *interface;		/* interface to capture (i.e. eth0)	*/
  char *filename;		/* filename to treat as an interface	*/
  char *outfile;		/* output filename			*/
  struct EncodingFunctions *enc;/* functions for the chosen encoding	*/
  pcap_dumper_t *d;		/* pcap dumper				*/
  pcap_t *p;			/* associated pcap_t			*/
};

struct Times {
  struct timeval wall;		/* wall clock time beginning a RT dump	*/
  struct timeval virt;		/* time of the first packet in a RT dump*/
  struct timeval off;		/* Offset between wall & virt		*/
};

struct EncodingFunctions {
  char *name;
  int (*init) (int argc, char *argv[]);
  void (*encode) (uint32_t *ip);
  void (*decode) (uint32_t *ip);
  void (*cleanup) ();
};

/* encodings.c */
extern struct EncodingFunctions encoding_table[];

/* dump.c */
void dump_open();
void dump(const struct pcap_pkthdr *ph, const u_char *pkt);
void dump_close();

/* capture.c */
void capture_cb(u_char *data, const struct pcap_pkthdr *cph, const u_char *cpkt);
void timed_cb(u_char *data, const struct pcap_pkthdr *ph, const u_char *pkt);

/* main.c */
extern struct Config config;
extern struct Times times;

#endif /* TCPURIFY_H */
