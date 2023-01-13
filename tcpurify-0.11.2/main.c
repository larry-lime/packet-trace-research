/****************************************************************************
 * 
 * tcpurify - main.c
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tcpurify.h"

void cleanup(int signum);
void usage();

/* This lives in libpcap, but we use it to print out our -v and -h messages
 * to let the user know what we were compiled against. */
extern char pcap_version[];

/* The following three structures are the global variables defined in
 * tcpurify.h.  config contains our configuration information (duh), networks
 * contains the information on requested address transformations, and times
 * is used for realtime playback. */
struct Config config = {
    0,          /* debug */
    1,          /* truncate */
    0,          /* reverse */
    0,          /* timed */
    0,          /* maxtime */
    0,          /* verify_cs */
    NULL,       /* interface */
    NULL,       /* filename */
    NULL,       /* outfile */
    NULL,       /* enc */
    NULL,       /* d */
    NULL,       /* p */
};

struct Times times;

int main(int argc, char *argv[])
{
  int opt, count = -1, i;
  char err[PCAP_ERRBUF_SIZE];

  while((opt = getopt(argc, argv, "i:f:r:o:w:c:T:dxtRhvV")) != -1) {
    switch(opt) {
     case 'i':
      config.interface = optarg;
      break;
     case 'f':
     case 'r':
      config.filename = optarg;
      break;
     case 'o':
     case 'w':
      config.outfile = optarg;
      break;
     case 'c':
      count = atoi(optarg);
      if(count < 0) {
	fprintf(stderr, "Invalid packet count %d\n", count);
	return(1);		/* Bye-bye */
      }
      break;
     case 'T':
      config.maxtime = atoi(optarg);
      break;
     case 'd':
      config.debug++;
      break;
     case 'x':
      config.truncate = 0;
      break;
     case 't':
      config.timed = 1;
      break;
     case 'R':
      config.reverse = 1;
      break;
     case 'h':
      usage();
      /* Never reached */
      break;
     case 'v':
      printf("tcpurify %s, libpcap %s\n", VERSION, pcap_version);
      return(0);		/* Exit the program */
     case 'V':
      config.verify_cs = 1;
      break;
     default:
      usage();
    }
  }
  if(config.filename && config.interface) {
    fprintf(stderr, "The -f option cannot be used with the -i option\n");
    return(1);			/* Exit 1 */
  }
  if(config.timed && !config.filename) {
    fprintf(stderr, "tcpurify: -t requires the -f option\n");
    return(1);			/* Doh, unsuccessful termination */
  }

  if (optind == argc) {
    usage ();
    return (1);
  } else {
    for (i = 0; encoding_table[i].name != NULL; i++) {
      if (strcmp (argv[optind], encoding_table[i].name) == 0) {
        config.enc = &encoding_table[i];
        break;
      }
    }
    if (config.enc == NULL) {
      fprintf (stderr, "Invalid encoding.  The recognized encodings are:\n");
      for (i = 0; encoding_table[i].name != NULL; i++) {
        fprintf (stderr, "  %s\n", encoding_table[i].name);
      }
      return (1);
    }
    if (config.reverse && config.enc->decode == NULL) {
      fprintf (stderr, "The %s encoding does not support decoding.\n",
               config.enc->name);
      return 1;
    }
    optind++;
  }
  
  if ((*config.enc->init) (argc - optind, argv + optind)) {
    fprintf (stderr, "Error initializing encoding '%s'\n", config.enc->name);
    return (1);
  }
  
  signal(SIGTERM, cleanup);
  signal(SIGINT, cleanup);
  signal(SIGHUP, cleanup);
  
  if(config.filename) {
    if((config.p = pcap_open_offline(config.filename, err)) == NULL) {
      fprintf(stderr, "Error opening tracefile %s: %s\n", 
	      config.filename, err);
      return(1);		/* Exit the program */
    }
  } else {
    if(config.interface == NULL) {
      if((config.interface = pcap_lookupdev(err)) == NULL) {
	fprintf(stderr, "Could not get capture interface: %s\n", err);
	return(1);		/* Exit the program */
      }
    }
    
    /* Open the given interface, get the 1st PKT_LEN bytes, do be 
     * promiscuous...  I have no idea what the 1000 is.  :-( */
    if((config.p = pcap_open_live(config.interface, PKT_LEN, 
			   1, 1000, err)) == NULL) {
      fprintf(stderr, "Error opening %s for capture: %s\n",
	      config.interface, err);
      return(1);		/* Exit the program */
    }
  }
  
  dump_open();
  
  if(config.timed) {
    gettimeofday(&times.wall, NULL);
    times.virt.tv_sec = 0;
    if(pcap_loop(config.p, count, timed_cb, NULL) < 0) {
      fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(config.p));
    }
  } else {
    if(pcap_loop(config.p, count, capture_cb, NULL) < 0) {
      fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(config.p));
    }
  }
  dump_close();
  
  return(0);
}

void cleanup(int signum)
{
  dump_close ();
  
  if(config.p) {
    pcap_close(config.p);
  }
  
  (*config.enc->cleanup) ();
  
  exit(0);
}

/* I think this should be obvious enough. */
void usage()
{
  fprintf(stderr, "tcpurify version %s\n", VERSION);
  fprintf(stderr, "libpcap version %s\n", pcap_version);
  fprintf(stderr,
"Usage: tcpurify [OPTIONS] <encoding> [ENCODING OPTIONS]\n"
"Where options consist of:\n"
"  -d\t\tdebug\n"
"  -x\t\tdisable IP packet truncation\n"
"  -R\t\treverse previous mapping (requires -m)\n"
"  -t\t\toutput packets from a dump file as if in real time\n"
"  -i interface\tread input from device interface\n"
"  -f filename\t-or-\n"
"  -r filename\tread input from file filename\n"
"  -o filename\t-or-\n"
"  -w filename\tsend output to file filename\n"
"  -c count\tcapture only count packets\n"
"  -T time\tMaximum time between real-time packets\n"
"  -V\t\tverify the TCP checksum and store success code in its place\n"
"  -h\t\tdisplay this message and exit\n"
"  -v\t\tdisplay version information and exit\n"
"\n"
" Current valid values for <encoding> are:\n"
"  none\t\tNo IP address transformation will be performed\n"
"  table\t\tSimple table-based transformation\n");
  exit(1);
}
