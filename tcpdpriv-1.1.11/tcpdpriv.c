/*
 * Copyright (c) 1996
 *	Ipsilon Networks, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Ipsilon Networks, Inc.
 * 4. The name of Ipsilon Networks, Inc., may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY IPSILON NETWORKS, INC., ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IPSILON NETWORKS, INC., BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef lint
static char rcsid[] =
    "@(#) $Header: /usr/home/minshall/src/mine/tcpdpriv/RCS/tcpdpriv.c,v 1.43 1997/08/28 00:07:14 minshall Exp $";
#endif

/*
 * tcpdpriv - make a tcpdump file private (so it can be shared)
 *
 * TODO:
 *
 *	1.  PRIVACY FOR LINK-LEVEL HEADER??? XXX ??? XXX ??? XXX ???
 *		(One method would be to have -L0 imply "convert to
 *		DLT_NULL; unforunately, libpcap doesn't support this.)
 *  	2.  -P|-T|-U >= 2
 *  	3.  Don't use tree for byte-wide counters; maybe not for 16-bit?
 *  	4.  If can tell via link hdr that is broadcast or multicast,
 *  	    	does that open up an attack on the destination net
 *  	    	encoding?
 *  	5.  Retain all zeros and all ones addresses?  (Actually, can
 *		you *safely* retain trailing 0s and trailing 1s?)
 *	6.  Use table to preserve classness.  (Actually, *without* this,
 *  	    	non class-D addresses may get mapped to class-D addresses?)
 *	8.  Should we retain local subnet broadcast information?
 *     11.  PRIVACY for TCP sequence numbers???
 *
 * $Id: tcpdpriv.c,v 1.43 1997/08/28 00:07:14 minshall Exp $
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(linux)
#define __FAVOR_BSD 1
#endif

#if	defined(SVR4)
#include <sys/statvfs.h>
#endif	/* defined(SVR4) */
#include <sys/param.h>
#include <sys/time.h>
#if	!defined(SVR4) && !defined(linux)
#include <sys/ucred.h>
#endif	/* !defined(SVR4) */
#include <sys/mount.h>
#include <sys/socket.h>
#if	defined(sun) || defined(linux)
#include <sys/vfs.h>
#endif	/* defined(sun) */

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#if	!defined(SVR4) && !defined(linux)
#include <sys/mbuf.h>
#endif	/* !defined(SVR4) */
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#if !defined(sun) && !defined(linux)
#include <net/slcompress.h>
#if	!defined(osf1)
#include <net/slip.h>
#endif	/* !defined(osf1) */
#include <netinet/if_fddi.h>
#include <net/if_llc.h>
#endif	/* !defined(sun) */

#include <netdb.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#if	defined(sun)
#include <memory.h>
#endif	/* defined(sun) */
#include <signal.h>

#include <pcap.h>

/*
 * deal with systems in which bpf_int32 and bpf_u_int32 are not defined
 */
#if ((PCAP_VERSION_MAJOR < 2) || (PCAP_VERSION_MINOR < 4))
typedef int bpf_int32;
typedef u_int bpf_u_int32;
#endif /* ((PCAP_VERSION_MAJOR < 2) || (PCAP_VERSION_MINOR < 4)) */



/*
 * general defines...
 */

#define	GETNETSHORT(p)	((*(u_char *)(p)<<8)|(*(u_char *)((p)+1)))
#define	EXTRACT_BIT(value,bitno) (((value)>>(32-(bitno)))&1)

#define  NUM(a)  (sizeof (a)/(sizeof (a)[0]))

/*
 * Support for TTLs
 */

/* TTLs are <= (so, <= 128 --> continent-local) */
#define	MCAST_TTL_NODE_LOCAL		0
#define	MCAST_TTL_LINK_LOCAL		1
#define	MCAST_TTL_SITE_LOCAL		32
#define	MCAST_TTL_CONTINENT_LOCAL	128

#define	MCAST_OPT_NODE_LOCAL		90
#define	MCAST_OPT_LINK_LOCAL		80
#define	MCAST_OPT_SITE_LOCAL		70
#define	MCAST_OPT_CONTINENT_LOCAL	20
#define	MCAST_OPT_GLOBAL		10

/*
 * given a TTL, determine a value of opt_mcastaddr that will pass
 * an address with that TTL through unchanged.
 */
#define	ttlTOopt(ttl)	(\
	((ttl) <= MCAST_TTL_NODE_LOCAL) ? MCAST_OPT_NODE_LOCAL : \
	(((ttl) <= MCAST_TTL_LINK_LOCAL) ? MCAST_OPT_LINK_LOCAL : \
	(((ttl) <= MCAST_TTL_SITE_LOCAL) ? MCAST_OPT_SITE_LOCAL : \
	(((ttl) <= MCAST_TTL_CONTINENT_LOCAL) ? MCAST_OPT_CONTINENT_LOCAL : \
	MCAST_OPT_GLOBAL))))

#define	optTOttlLOW(opt) (\
	((opt) == MCAST_OPT_NODE_LOCAL) ? 0 : \
	(((opt) == MCAST_OPT_LINK_LOCAL) ? (MCAST_TTL_NODE_LOCAL+1) : \
	(((opt) == MCAST_OPT_SITE_LOCAL) ? (MCAST_TTL_LINK_LOCAL+1) : \
	(((opt) == MCAST_OPT_CONTINENT_LOCAL) ? (MCAST_TTL_SITE_LOCAL+1) : \
	(MCAST_TTL_CONTINENT_LOCAL+1)))))

#define	optTOttlHIGH(opt) (\
	((opt) == MCAST_OPT_NODE_LOCAL) ? MCAST_TTL_NODE_LOCAL : \
	(((opt) == MCAST_OPT_LINK_LOCAL) ? MCAST_TTL_LINK_LOCAL : \
	(((opt) == MCAST_OPT_SITE_LOCAL) ? MCAST_TTL_SITE_LOCAL : \
	(((opt) == MCAST_OPT_CONTINENT_LOCAL) ? MCAST_TTL_CONTINENT_LOCAL : \
	255))))

/*
 * byte ordering macros...
 */
#if	!defined(BYTE_ORDER)
/* OK, need to do byte order stuff... */
#define	LITTLE_ENDIAN	1234	/* LSB first: i386, vax */
#define	BIG_ENDIAN	4321	/* MSB first: 68000, ibm, net */

#if	defined(vax) || defined(i386)
#define	BYTE_ORDER	LITTLE_ENDIAN
#endif
#if	defined(mc68000) || defined(sparc)
#define	BYTE_ORDER	BIG_ENDIAN
#endif
#endif /* !defined(BYTE_ORDER) */

#if	!defined(NTOHL)
#if	(BYTE_ORDER == BIG_ENDIAN)

#define	NTOHL(x)
#define	NTOHS(x)
#define	HTONL(x)
#define	HTONS(x)

#endif	/* BYTE_ORDER == BIG_ENDIAN */

#if	(BYTE_ORDER == LITTLE_ENDIAN)

#define	NTOHL(x)	(x) = ntohl((u_long)x)
#define	NTOHS(x)	(x) = ntohs((u_short)x)
#define	HTONL(x)	(x) = htonl((u_long)x)
#define	HTONS(x)	(x) = htons((u_short)x)

#endif	/* (BYTE_ORDER == LITTLE_ENDIAN) */
#endif	/* !defined(NTOHL) */

/*
 * function prototypes
 */

    /* macros for ansi/non-ansi compatibility */
#ifndef __P
#if defined(_USE_PROTOTYPES) && (defined(__STDC__) || defined(__cplusplus))
#define	__P(protos)	protos		/* full-blown ANSI C */
#else
#define	__P(protos)	()		/* traditional C preprocessor */
#endif
#endif

#if	defined(sun)
extern long random __P((void));
#endif	/* defined(sun) */


#if	defined(sun) && !defined(SVR4)
int 	fflush __P((FILE *stream));
int 	_flsbuf __P((int, FILE*));
int	fprintf __P((FILE *, const char *, ...));
int	getopt __P((int, char * const *, const char *));
extern int optind, opterr;
void	pcap_perror(pcap_t *, char *);
int	pclose __P((FILE *stream));
void	perror __P((const char *));
FILE	*popen __P((const char *command, const char *type));
int	printf __P((const char *, ...));
int 	setitimer __P((int which, struct itimerval value,
				    struct itimerval ovalue));
void	srandom __P((unsigned));
int	sscanf __P((const char *str, const char *format, ...));
int	statfs __P((const char *, struct statfs *));
#endif	/* defined(sun) && !defined(SVR4) */

#if	defined(sun)		/* why not defined in Solaris? */
int	gettimeofday __P((struct timeval *, struct timezone *));
#endif	/* defined(sun) */

/*
 * typedefs...
 */

typedef struct node node_t, *node_p;	/* type of a tree node */

struct node {
    u_long
	input,		/* input value */
	output;		/* output value */
    node_p
	down[2];	/* children */
};

typedef struct nodehdr nodehdr_t, *nodehdr_p;	/* type of a tree */

struct nodehdr {
    u_long
	flags,		/* see below */
	addr_mask,	/* mask of bits to copy from input */
	counter,	/* for NH_FL_COUNTER */
	bump,		/* amount by which to bump counter */
	cur_input;	/* what address is currently being masked */
    node_p
	head;
};

#define	NH_FL_RANDOM_PROPAGATE	1	/* propagate random number down */
#define	NH_FL_COUNTER		2	/* bump a counter */

/*
 * globally scoped variables
 */

/*
 * Trees for addressing.
 *
 * addr_propagate is for -A50.
 *
 * The 0x01000000 is to compensate for a bug in tcpdump (where
 * it has problems dealing with IP addresses that have zero (0)
 * in the high order byte).
 */

nodehdr_t
    addr_propagate = { NH_FL_RANDOM_PROPAGATE, 0xffffffff, 0x01000000 },
    addr_whole = { NH_FL_COUNTER, 0xffffffff, 0x01000000 },
	addr_upper = { NH_FL_COUNTER, 0xffff0000, 0x01000000 },
	addr_lower = { NH_FL_COUNTER, 0x0000ffff, 0},
	    addr_byte_0 = { NH_FL_COUNTER, 0xff000000, 0 },
	    addr_byte_1 = { NH_FL_COUNTER, 0x00ff0000, 0 },
	    addr_byte_2 = { NH_FL_COUNTER, 0x0000ff00, 0 },
	    addr_byte_3 = { NH_FL_COUNTER, 0x000000ff, 0 };

    /* trees for tcp ports */
nodehdr_t
    tcpport_whole,
    tcpport_byte_0, tcpport_byte_1;

    /* trees for udp ports */
nodehdr_t
    udpport_whole,
    udpport_byte_0, udpport_byte_1;

    /* options (from command line) */
int
    opt_ipaddr, opt_mcastaddr, opt_tcpports, opt_udpports,
    opt_class, opt_options;

int
    qflag = 0;		/* -q */

int
    pcap_dlt,		/* data link type of input file */
    pcap_snap;		/* snap length of input file */

    /* statistics */
int
    pktsin,		/* packets read in */
    pktsout,		/* packets written out */
    tooshort,		/* too short to be processed -- dropped */
    uncoded;		/* unsupported protocols -- dropped */

    /* FDDI support */
/*
 * This is a place where pcap is a bit messed up (should be two DLTs).
 */

#if defined(ultrix) || defined(__alpha)
#define FDDIPAD 3
#else
#define FDDIPAD 0
#endif

int fddipad = FDDIPAD;


#if !defined(FDDIFC_LLC_ASYNC)
/*
 * if we can't find any FDDI header files...
 */

struct fddi_header {
    u_char  fddi_fc;
    u_char  fddi_dhost[6];		/* destination */
    u_char  fddi_shost[6];		/* source */
};

#define	FDDIFC_LLC_ASYNC    0x50
#endif	/* !defined(FDDIFC_LLC_ASYNC) */

#if !defined(FDDIFC_CLFF)
#define	FDDIFC_CLFF 	    0xf0    	/* length/class/format bits */
#endif /* !defined(FDDIFC_CLFF) */


#if !defined(LLC_UI)
/*
 * if we can't find LLC header files...
 *
 * (this is a very minimal LLC header, sufficient only for our
 * limited needs.)
 */

struct llc {
    u_char  llc_dsap;	    	    	/* source SAP (service access point) */
    u_char  llc_ssap;	    	    	/* destination SAP */
    u_char  llc_control;		/* control byte (in some frames) */
};

#define	LLC_UI	    	0x03	    	/* this is an unnumbered info frame */
#define	LLC_SNAP_LSAP	0xaa		/* SNAP SAP */
#endif /* !defined(LLC_UI) */


    /* packet pointers */
u_char *pktbuffer;	/* where packet buffer is */
u_char *packetp;	/* where packet came from */
u_char *snapend;	/* last byte in packet */

pcap_t *pc;		/* our input file */


/*
 *   R   A   N   D   O   M
 */


/*
 * return 32-bits of random()
 *
 * (on most 32-bit machines, random() returns only 31 bits)
 */

static long
rand32()
{
#if	defined(SVR4)
    return ((lrand48()&0xffff)<<15)|(lrand48()&0xfff);
#else	/* defined(SVR4) */
    return ((random()&0xffff)<<16)|(random()&0xffff);
#endif	/* defined(SVR4) */
}

/*
 * run through an area, accumulating the values into a seed.
 */

static unsigned
rand_accum(unsigned prev, unsigned *px, int ints)
{
    /* now, sum it all, shifting all the time */
    while (ints--) {
	prev ^= *px++;
	prev = (prev<<1)|(prev>>31);
    }
    return prev;
}


/*
 * at startup, generate a seed for the random number generator
 *
 * (it is somewhat amusing how driven i am to say "sum = 0" and
 * "memset(&x, 0, sizeof x)" below, given that i *want* random
 * bits...)
 */

static void
rand_start(void)
{
    struct {
	struct timeval tv;
	struct timezone tz;
	uid_t uid;
	pid_t pid;
    } x;
    unsigned sum = 0;
    int n, gotline;
    unsigned line[200/sizeof (unsigned)];
    FILE *pfd;

    memset(&x, 0, sizeof x);

    if (gettimeofday(&x.tv, &x.tz) == -1) {
	perror("gettimeofday");
	exit(1);
    }
    x.uid = getuid();
    x.pid = getpid();

    /* now, sum it all, shifting all the time */
    sum = rand_accum(sum, (unsigned *)&x, sizeof x/sizeof(unsigned));

	/*
	 * we run through all the mounted file systems
	 * (as reported by mount, anyway) doing a stat
	 * on them.  note that SVR4 uses "mountpoint on device",
	 * whereas BSD uses "device on mountpoint".
	 */

    pfd = popen("/bin/mount", "r");
    if (pfd == NULL) {
	pfd = popen("mount", "r");
	if (pfd == NULL) {
	    fprintf(stderr, "unable to popen() /sbin/mount or mount");
	    perror("");
	    exit(1);
	}
    }

    gotline = 0;
    while (fgets((char *)line, sizeof line, pfd) != NULL) {
#if	!defined(SVR4)
	struct statfs stat;
#else	/* !defined(SVR4) */
	struct statvfs stat;
#endif	/* !defined(SVR4) */
	char first[sizeof line], second[sizeof line];

	n = sscanf((char *)line, "%s on %s %*s\n", first, second);
	if (n != 2) {
	    fprintf(stderr, "ill-formatted output from mount(1) command\n");
	    exit(1);
	}
#if	!defined(SVR4)
	n = statfs(second, &stat);
#else	/* !defined(SVR4) */
	n = statvfs(first, &stat);
#endif	/* !defined(SVR4) */
	if (n == -1) {
	    perror("statfs");
	    exit(1);
	}
	sum = rand_accum(sum, (unsigned *)&stat, sizeof stat/sizeof (unsigned));
	gotline = 1;
    }
    pclose(pfd);
    if (gotline == 0) {	/* nothing in output from mount command... */
	fprintf(stderr, "no output from mount(1) command\n");
	exit(1);
    }

	/*
	 * now, do the same as mount, but this time with "netstat -in"
	 */

    if (((pfd = popen("netstat -in", "r")) == NULL) &&
		((pfd = popen("/bin/netstat -in", "r")) == NULL) &&
		((pfd = popen("/usr/ucb/netstat -in", "r")) == NULL) &&
		((pfd = popen("/usr/sbin/netstat -in", "r")) == NULL) &&
		((pfd = popen("/usr/bin/netstat -in", "r")) == NULL)) {
	fprintf(stderr,
	   "unable to popen {,/bin/,/usr/ucb/,/usr/sbin,/usr/bin/}netstat -in");
	perror("");
	exit(1);
    }
    gotline = 0;
    while (fgets((char *)line, sizeof line, pfd) != NULL) {
	sum = rand_accum(sum, line, strlen((char *)line)/sizeof (unsigned));
	gotline = 1;
    }
    pclose(pfd);
    if (gotline == 0) {
	fprintf(stderr, "no output from 'netstat -in' command\n");
	exit(1);
    }

#if	defined(SVR4)
    srand48(sum);
#else	/* defined(SVR4) */
    srandom(sum);
#endif	/* defined(SVR4) */
}

/*
 *   U   T   I   L   I   Y         R   O   U   T   I   N   E   S
 */

/*
 * like ffs(3), but looking from the MSB.
 */

int
bi_ffs(u_long value)
{
    int add = 0;
    static u_char bvals[] = { 0, 4, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1 };

    if ((value&0xFFFF0000) == 0) {
	if (value == 0) {	/* zero input ==> zero output */
	    return 0;
	}
	add += 16;
    } else {
	value >>= 16;
    }
    if ((value&0xFF00) == 0) {
	add += 8;
    } else {
	value >>= 8;
    }
    if ((value&0xF0) == 0) {
	add += 4;
    } else {
	value >>= 4;
    }
    return add+bvals[value&0xf];
}

/*
 * Subtract a quantity from a standard IP checksum (network order)
 *
 * (We define the arguments u_*long* (rather than u_short)
 * to allow us operate inplace on [hopefully] 32 bit operands.)
 */

static u_short
cksum_subtract(u_long sum, u_long subtrahend)
{
    NTOHS(sum);
    NTOHL(subtrahend);
    subtrahend = ~subtrahend;
    subtrahend = (subtrahend&0xffff) + ((subtrahend>>16)&0xffff);
    sum = (0xffff&~sum) + subtrahend;
    sum = (sum&0xffff)+((sum>>16)&0xffff);
    sum = (sum&0xffff)+((sum>>16)&0xffff);      /* That's enough */

    sum = 0xffff&~sum;
    HTONS(sum);
    return (u_short)sum;
}


/*
 * Add a quantity to a standard IP checksum (network order)
 *
 * (We define the arguments u_*long* (rather than u_short)
 * to allow us operate inplace on [hopefully] 32 bit operands.)
 */

static u_short
cksum_add(u_long sum, u_long well)
{
    NTOHS(sum);
    NTOHL(well);
    well = (well&0xffff) + ((well>>16)&0xffff);
    sum = (0xffff&~sum) + well;
    sum = (sum&0xffff)+((sum>>16)&0xffff);
    sum = (sum&0xffff)+((sum>>16)&0xffff);      /* That's enough */

    sum = 0xffff&~sum;
    HTONS(sum);
    return (u_short)sum;
}

/*
 * Adjust the checksum based on a second sum (network order)
 */

static u_short
cksum_adjust(u_long sum, u_long sum2)
{
    return cksum_subtract(sum, sum2);		/* XXX just for now!!! */
}

/*
 * parse a string to determine the number of hh:mm:ss to run, and
 * then set an alarm to trigger after that number of seconds.
 */

void
setalarm(char *alarm)
{
    int n, aa, bb, cc, secs;
    struct itimerval itv;

#if	!defined(ITIMER_REAL)
#define	ITIMER_REAL	0
#endif	/* !defined(ITIMER_REAL) */

    n = sscanf(alarm, "%d:%d:%d", &aa, &bb, &cc);
    switch (n) {
    case 0:
	fprintf(stderr, "Invalid alarm value %s\n", alarm);
	exit(2);
	break;
    case 1:
	secs = aa;
	break;
    case 2:
	secs = (aa*60)+bb;
	break;
    case 3:
	secs = (aa*60*60)+(bb*60)+cc;
	break;
    default:
	fprintf(stderr, "Invalid alarm value %s\n", alarm);
	exit(2);
	break;
    }

    itv.it_value.tv_sec = secs;
    itv.it_value.tv_usec = 0;
    itv.it_interval.tv_usec = itv.it_interval.tv_sec = 0;

    if (setitimer(ITIMER_REAL, &itv, 0) < 0) {
	perror("setitimer");
	exit(2);
    }
}


/*
 *   T   R   E   E         R   O   U   T   I   N   E   S
 */

static node_p
newnode(void)
{
    node_p node;

    node = (node_p) malloc(sizeof *node);

    if (node == 0) {
	fprintf(stderr, "malloc failed %s:%d\n", __FILE__, __LINE__);
	exit(2);
    }
    return node;
}


static void
freetree(node_p node)
{
    node_p next;

    while (node) {
	next = node->down[0];
	if (node->down[1]){
	    freetree(node->down[1]);
	}
	free(node);
	node = next;
    }
}

/*
 *    M   A   S   K   I   N   G
 */

/*
 * figure out what the output for a given input should be.
 *
 * 	value		the old output
 *	flip		bit (MSB == 0) at which inputs differ
 *	hdr		the tree we are in
 *
 * note that only hide_addr() sets cur_input (and, that only the "addr"
 * trees set addr_mask).
 *
 * also, addr_mask is munged (by lookup_init()) to have at most
 * opt_class high order bits set as one.
 */

static inline u_long
make_output(u_long value, int flip, nodehdr_p hdr)
{
    if (hdr->flags&NH_FL_RANDOM_PROPAGATE) {
			/*
			 * the output is:
			 * bits 1-(flip-1):	copied from value
			 * bit  flip:		flip bit (XOR with 1) in value
			 * bits (flip+1)-32:	random
			 */
	if (flip == 32) {
	    return value^1;
	} else {		/* get left AND flipped bit */
	    return ((((value>>(32-flip))^1)<<(32-flip)) |
			((rand32()&0x7fffffff)>>flip)); /* and get right part */
	}
    } else if (hdr->flags&NH_FL_COUNTER) {
	hdr->counter += hdr->bump;
	/* now, do we need to copy any bits from head? */
	if (hdr->addr_mask) {
	    int n;
	    u_long m;
	    /*
	     * retain consecutive high order ONE (1) bits from
	     * cur_input.  number of consecutive high order one
	     * bits to retain is constrained by addr_mask.
	     */
	    n = bi_ffs(~hdr->cur_input);	/* n == first ZERO (0) bit */
	    if (n) {
		m = hdr->cur_input>>(32-n);
		return hdr->counter|((m<<(32-n))&hdr->addr_mask);
	    } else {
		/* n == 0 ==> cur_input all ones */
		return hdr->counter&hdr->addr_mask;
	    }
	}
	return hdr->counter;
    } else {
	fprintf(stderr, "unknown flags field %s:%d\n", __FILE__, __LINE__);
	exit(2);
    }
}


/*
 * make a peer that corresponds to input.  return input's node.
 */

static inline node_p
make_peer(u_long input, node_p old, nodehdr_p hdr)
{
    node_p down[2];
    int swivel, bitvalue;

    /*
     * become a peer
     * algo: create two nodes, the two peers.  leave orig node as
     * the parent of the two new ones.
     */

    down[0] = newnode();
    down[1] = newnode();

    swivel = bi_ffs(input^old->input);
    bitvalue = EXTRACT_BIT(input, swivel);

    down[bitvalue]->input = input;
    down[bitvalue]->output = make_output(old->output, swivel, hdr);
    down[bitvalue]->down[0] = down[bitvalue]->down[1] = 0;

    *down[1-bitvalue] = *old;	    /* copy orig node down one level */

    old->input = down[1]->input;    /* NB: 1s to the right (0s to the left) */
    old->output = down[1]->output;
    old->down[0] = down[0];	    /* point to children */
    old->down[1] = down[1];

    return down[bitvalue];
}

/*
 *   L   O   O   K   U   P
 */

/*
 * initialize a lookup structure.
 *
 * addr_mask is non-zero if this is a header for IP addresses,
 * in which case it is a mask of the bits covered in the IP
 * address by this header.
 */

static void
lookup_init(nodehdr_p hdr)
{
    node_p node;

    if (hdr->head) {
	freetree(hdr->head);
	hdr->head = 0;
    }

    /*
     * this is all a bit cryptic, so here's the deal
     *
     * if addr_mask is zero, or doesn't cover any of the
     * classness bits preserved by -Cnn, then we create
     * exactly one node whose input value is zero, and whose
     * output value is random.
     *
     * on the other hand, if addr_mask covers some of the
     * classness bits, we create a node which performs the
     * identity map on those bits in addr_mask covered by
     * -Cnn and the rest of which is random.
     */

    hdr->head = newnode();
    node = hdr->head;

    /* if this is high order address byte, prime classness if needed */
    if (hdr->addr_mask) {
	/* compute bump as lsb of addr_mask */
	hdr->bump = 1<<(ffs(hdr->addr_mask)-1);	/* NOTE -- traditional ffs() */
	if (hdr->flags == NH_FL_COUNTER) {
	    node->output = hdr->bump;
	} else {
	    /* whatever we do, don't pick up any bits outside of addr_mask */
		/* zeros for high order opt_class bits */
	    node->output = rand32()>>opt_class;
		/* no bits outside of addr_mask */
	    node->output &= hdr->addr_mask;
	}
	if (opt_class) {
	    /* extract bits in addr_mask covered by opt_class */
	    hdr->addr_mask = hdr->addr_mask>>(32-opt_class);
	    hdr->addr_mask = hdr->addr_mask<<(32-opt_class);
	    node->input = hdr->addr_mask;
	    node->output |= hdr->addr_mask;
	} else {
	    hdr->addr_mask = 0;
	    node->input = 0;
	}
    } else {
	node->input = 0;
	/*
	 * by using rand32(), we get bit 0 (MSB) randomized;
	 * passing 0 wouldn't do at all...
	 */
	node->output = rand32();
	hdr->bump = 1;
    }

    node->down[0] = node->down[1] = 0;
}


/*
 * EVERY NON-LEAF NODE HAS ***2*** CHILDREN!!!
 * (otherwise, the code below dies badly!)
 */

u_long
lookup(u_long input, nodehdr_p hdr)
{
    node_p node;
    int swivel;

    node = hdr->head;	/* non-zero, 'cause lookup_init() already called */
    if (hdr->head == 0) {	/* (but...) */
	fprintf(stderr, "unexpected zero head %s:%d\n", __FILE__, __LINE__);
    }

    while (node) {
	if (input == node->input) {	/* we found our node! */
	    return node->output;
	}
	if (node->down[0] == 0) {	/* need to descend, but can't */
	    node = make_peer(input, node, hdr);		/* create a peer */
	} else {
	    /* swivel is the first bit the left and right children differ in */
	    swivel = bi_ffs(node->down[0]->input^node->down[1]->input);
	    if (bi_ffs(input^node->input) < swivel) {/* input differs earlier */
		node = make_peer(input, node, hdr);  /* make a peer */
	    } else if (input&(1<<(32-swivel))) {
		node = node->down[1];	    /* NB: 1s to the right */
	    } else {
		node = node->down[0];	    /* NB: 0s to the left */
	    }
	}
    }

    /* ??? should not occur! */
    fprintf(stderr, "unexpected loop termination %s:%d\n", __FILE__, __LINE__);
    exit(1);
}

#ifdef	DEBUG
void
dumptable(node_p node, int level)
{
    int i;

    while (node) {
	for (i = 0; i < level; i++) {
	    putchar('.');
	}
	printf("0x%lx 0x%lx\n", node->input, node->output);
	level++;
	if (node->down[0]) {
	    dumptable(node->down[0], level);
	}
	node = node->down[1];
    }
}
#endif	/* DEBUG */

/*
 *   H   I   D   I   N   G
 */


u_long
hide_addr(u_long addr, u_int ttl)
{
    u_long answer;

    if (addr == INADDR_ANY || addr == INADDR_BROADCAST
	|| (IN_CLASSD(addr) && (ttl >= optTOttlLOW(opt_mcastaddr)))) {
      return addr;
    }

    switch (opt_ipaddr) {
    case 0:
	addr_whole.cur_input = addr;
	answer = lookup(addr, &addr_whole);
	break;
    case 1:
	addr_upper.cur_input = addr_lower.cur_input = addr;
	answer = lookup(addr&0xffff0000, &addr_upper) |
			    lookup(addr&0xffff, &addr_lower);
	break;
    case 2:
	addr_byte_0.cur_input =
	    addr_byte_1.cur_input =
	    addr_byte_2.cur_input =
	    addr_byte_3.cur_input = addr;
	/* if i had a hammer... */
	answer =
		lookup(addr&0xff000000, &addr_byte_0) |
		lookup(addr&0x00ff0000, &addr_byte_1) |
		lookup(addr&0x0000ff00, &addr_byte_2) |
		lookup(addr&0x000000ff, &addr_byte_3);
	break;
    case 50:
	addr_propagate.cur_input = addr;
	answer = lookup(addr, &addr_propagate);
	break;
    case 99:
	answer = addr;
	break;
    default:
	fprintf(stderr, "unknown opt_ipaddr %s:%d\n", __FILE__, __LINE__);
	exit(1);
    }

    return answer;
}

u_short
hide_port(u_short port, nodehdr_p whole, nodehdr_p msb, nodehdr_p lsb, int opt)
{
    switch (opt) {
    case 0:
	return lookup(port, whole);
    case 1:
	return (lookup((port>>8)&0xff, msb)<<8) |
			    lookup(port&0xff, lsb);
    case 99:
	return port;
    default:
	fprintf(stderr, "unknown ports %s:%d\n", __FILE__, __LINE__);
	exit(1);
    }
}


u_short
hide_tcpport(u_short tcpport)
{
    return hide_port(tcpport,
	    &tcpport_whole, &tcpport_byte_0, &tcpport_byte_1, opt_tcpports);
}

u_short
hide_udpport(u_short udpport)
{
    return hide_port(udpport,
	    &udpport_whole, &udpport_byte_0, &udpport_byte_1, opt_udpports);
}


static u_char *
hide_tcpoptions(u_char *p, int caplen, int length, struct tcphdr *tcp)
{
    u_short *usp;
    int optlen;
    u_long sumoff;

    usp = (u_short *)p;
    optlen = (tcp->th_off*4)-sizeof *tcp;
    sumoff = 0;		/* reset this... */
    while ((optlen >= 2) && (caplen >= 2)) {
        if (opt_options == 0) {
	    sumoff = cksum_subtract(sumoff, *usp);
	    *usp = ntohs(0x0101);  /* no ops (doesn't need ntohs(), but...) */
	    sumoff = cksum_add(sumoff, *usp);
	}
	usp++; optlen -= 2; caplen -= 2;
    }
    tcp->th_sum = cksum_adjust(tcp->th_sum, sumoff);

    return (u_char *)usp;
}


static u_char *
hide_ipoptions(u_char *p, int caplen, int length, struct ip *ip)
{
    u_short *usp;
    int optlen;

    usp = (u_short *)p;
    optlen = (ip->ip_hl*4)-sizeof *ip;
    while ((optlen >= 2) && (caplen >= 2)) {
        if (opt_options == 0) {
	    ip->ip_sum = cksum_subtract(ip->ip_sum, *usp);
	    *usp = ntohs(0x0101);  /* no ops (doesn't need ntohs(), but...) */
	    ip->ip_sum = cksum_add(ip->ip_sum, *usp);
	}
	usp++; optlen -= 2; caplen -= 2;
    }
    return (u_char *)usp;
}

/*
 *   T   C   P
 */

/*
 * Munge a TCP header.
 *
 * Input:
 *	p		location of first byte of TCP header
 *	caplen		bytes (from p) captured
 *	length		bytes (from p) in current datagram (may not be captured)
 *	phoffset	how much pseudo header checksum changed during
 *			IP munging
 *
 * Output:
 *  	pointer to byte *past* last byte munged (so, first byte of
 *  	    TCP user data)
 */

static u_char *
dumptcp(u_char *p, int caplen, int length, u_long phoffset)
{
    u_short inport, outport;
    struct tcphdr *tcp = (struct tcphdr *)p;

    /* source port */
    if (caplen < 2) {
	return p+caplen;
    }
    inport = ntohs(tcp->th_sport);
    outport = hide_tcpport(inport);
    if (inport != outport) {
	phoffset = cksum_subtract(phoffset, tcp->th_sport);
	tcp->th_sport = htons(outport);
	phoffset = cksum_add(phoffset, tcp->th_sport);
    }
    caplen -= 2; length -= 2; p += 2;

    /* destination port */
    if (caplen < 2) {
	return p+caplen;
    }
    inport = ntohs(tcp->th_dport);
    outport = hide_tcpport(inport);
    if (inport != outport) {
	phoffset = cksum_subtract(phoffset, tcp->th_dport);
	tcp->th_dport = htons(outport);
	phoffset = cksum_add(phoffset, tcp->th_dport);
    }
    caplen -= 2; length -= 2; p += 2;

    /* seq, ack, off, flags, win */
    if (caplen < 12) {
	return p+caplen;
    }
    caplen -= 12; length -= 12; p += 12;

    /* sum */
    if (caplen < 2) {
	return p+caplen;
    }
    tcp->th_sum = cksum_adjust(tcp->th_sum, phoffset);
    caplen -= 2; length -= 2; p += 2;

    /* urgent pointer */
    if (caplen < 2) {
	return p+caplen;
    }
    caplen -= 2; length -= 2; p += 2;

    /* now, deal with options... */
    if ((tcp->th_off*4) > sizeof *tcp) {
	u_char *newp = hide_tcpoptions(p, caplen, length, tcp);
	int diff = newp-p;

	p += diff; caplen -= diff; length -= diff;
    }

    return p;
}

/*
 *    U   D   P
 */


/*
 * dump a udp packet.  we don't do much, just mask the ports
 * and update the checksum (if necessary).
 *
 * Input:
 *	p		location of first byte of UDP header
 *	caplen		bytes (from p) captured
 *	length		bytes (from p) in current datagram (may not be captured)
 *	phoffset	how much pseudo header checksum changed during
 *			IP munging
 *
 * Output:
 *  	pointer to byte *past* last byte munged (so, first byte of
 *  	    UDP user data)
 */

static u_char *
dumpudp(u_char *p, int caplen, int length, u_long phoffset)
{
    u_short inport, outport;
    struct udphdr *udp = (struct udphdr *)p;

    /* source port */
    if (caplen < 2) {
	return p+caplen;
    }
    inport = ntohs(udp->uh_sport);
    outport = hide_udpport(inport);
    if (inport != outport) {
	phoffset = cksum_subtract(phoffset, udp->uh_sport);
	udp->uh_sport = htons(outport);
	phoffset = cksum_add(phoffset, udp->uh_sport);
    }
    caplen -= 2; length -= 2; p += 2;

    /* destination port */
    if (caplen < 2) {
	return p+caplen;
    }
    inport = ntohs(udp->uh_dport);
    outport = hide_udpport(inport);
    if (inport != outport) {
	phoffset = cksum_subtract(phoffset, udp->uh_dport);
	udp->uh_dport = htons(outport);
	phoffset = cksum_add(phoffset, udp->uh_dport);
    }
    caplen -= 2; length -= 2; p += 2;

    /* length */
    if (caplen < 2) {
	return p+caplen;
    }
    caplen -= 2; length -= 2; p += 2;
    /* nothing to do with length */

    /* checksum */
    if (caplen < 2) {
	return p+caplen;
    }
    /* deal with checksum ... */
    if (udp->uh_sum != 0) {
	udp->uh_sum = cksum_adjust(udp->uh_sum, phoffset);
    }
    caplen -= 2; length -= 2; p += 2;

    /* don't return any UDP data */
    return p;
}

/*
 *   I   P
 */

/*
 * this is an IP packet --- output it securely.
 *
 * Input:
 *	p		location of first byte of IP header
 *	caplen		bytes (from p) captured
 *	length		bytes (from p) in current datagram (may not be captured)
 *
 * Output:
 *  	pointer to byte *past* last byte munged (so, first byte of
 *  	    IP payload not munged by dumpip() or any of its "children")
 */


static u_char *
dumpip(u_char *p, int caplen, int length)
{
    struct ip *ip;
    u_long inaddr, outaddr;
    u_short phoffset = 0;
    int foff;

    if (caplen < sizeof (struct ip)) {
	tooshort++;
	return p;
    }

    ip = (struct ip *)p;
    caplen -= sizeof *ip;
    length -= sizeof *ip;
    p += sizeof *ip;

    inaddr = ntohl(ip->ip_src.s_addr);
    outaddr = hide_addr(inaddr, ip->ip_ttl);
    if (inaddr != outaddr) {
	/*
	 * need to redo checksum (both for keeping tcpdump
	 * from thinking there is a checksum error, *AND*
	 * to maintain secrecy).  thank you, Vern!
	 */
	phoffset = cksum_subtract(phoffset, ip->ip_src.s_addr);
	ip->ip_src.s_addr = htonl(outaddr);
	phoffset = cksum_add(phoffset, ip->ip_src.s_addr);
    }

    inaddr = ntohl(ip->ip_dst.s_addr);
    outaddr = hide_addr(inaddr, ip->ip_ttl);
    if (inaddr != outaddr) {
	/*
	 * need to redo checksum (both for keeping tcpdump
	 * from thinking there is a checksum error, *AND*
	 * to maintain secrecy).  thank you, Vern!
	 */
	phoffset = cksum_subtract(phoffset, ip->ip_dst.s_addr);
	ip->ip_dst.s_addr = htonl(outaddr);
	phoffset = cksum_add(phoffset, ip->ip_dst.s_addr);
    }

    if (phoffset) {
	ip->ip_sum = cksum_adjust(ip->ip_sum, phoffset);
    }

    if ((ip->ip_hl*4) > sizeof *ip) {		/* options! */
	u_char *newp = hide_ipoptions(p, caplen, length, ip);
	int diff = newp-p;

	p += diff; caplen -= diff; length -= diff;
    }

    foff = ntohs(ip->ip_off);

    if ((caplen > 0) && ((foff & IP_OFFMASK) == 0)) {
	switch (ip->ip_p) {
	case IPPROTO_TCP:
	    p = dumptcp(p, caplen, length, phoffset);
	    break;
	case IPPROTO_UDP:
	    p = dumpudp(p, caplen, length, phoffset);
	    break;
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif	/* ndef IPPROTO_IPIP */
	case IPPROTO_IPIP:
	    p = dumpip(p, caplen, length);
	    break;
	default:
	    break;
	}
    }

    return p;
}

/*
 *   D   U   M   P   E   R
 */


/*
 * this routine is largely cribbed from various bits and pieces of
 * tcpdump(1).
 *
 * also, we keep to much of the tcpdump internal conventions, since
 * the form of this looks a lot like that of tcpdump (since the problem
 * is basically the same).
 */

static void
dumper(u_char *user, const struct pcap_pkthdr *inh, const u_char *inp)
{
#if !defined(SLIP_HDRLEN)
#define	SLIP_HDRLEN	16
#endif /* !defined(SLIP_HDRLEN) */

#define	PPP_HDRLEN	4
#define	NULL_HDRLEN	4
#define FDDI_HDRLEN	13		/* nice round number... */

    int caplen = inh->caplen;
    int length = inh->len;
    struct ether_header *ep;
    struct fddi_header *fddip;
    u_short ether_type;
    struct pcap_pkthdr ourh = *inh, *h = &ourh;
    u_char *p;
    static u_char SNAPHDR[] = { LLC_SNAP_LSAP, LLC_SNAP_LSAP, LLC_UI, 0, 0, 0 };

    pktsin++;

    if (caplen > pcap_snap) {
	fprintf(stderr, "packet too large %s:%d\n", __FILE__, __LINE__);
	exit(2);
    }

    memcpy(pktbuffer, inp, caplen);
    p = pktbuffer;

    packetp = p;		/* where packet started */
    snapend = p + caplen;	/* where packet ends */

    switch (pcap_dlt) {
    case DLT_EN10MB:
	if (caplen < sizeof (struct ether_header)) {
	    tooshort++;
	    return;
	}
	ep = (struct ether_header *)p;
	p += sizeof *ep;
	caplen -= sizeof *ep;
	length -= sizeof *ep;
	ether_type = ntohs(ep->ether_type);
	if (ether_type == 0x800) {	/* oh, good! */
	    p = dumpip(p, caplen, length);
	} else {
	    uncoded++;
	    return;
	}
	break;
    case DLT_SLIP:
	if (caplen < SLIP_HDRLEN) {
	    tooshort++;
	    return;
	}
	p = dumpip(p+SLIP_HDRLEN, caplen-SLIP_HDRLEN, length-SLIP_HDRLEN);
	break;
    case DLT_PPP:
	if (caplen < PPP_HDRLEN) {
	    tooshort++;
	    return;
	}
	/* XXX -- how do we know it is IP traffic? */
	p = dumpip(p+PPP_HDRLEN, caplen-PPP_HDRLEN, length-PPP_HDRLEN);
	break;
    case DLT_FDDI:
	if (caplen < FDDI_HDRLEN) {
	    tooshort++;
	    return;
	}
	fddip = (struct fddi_header *)p;
	length -= FDDI_HDRLEN;
	p += FDDI_HDRLEN;
	caplen -= FDDI_HDRLEN;
	if ((fddip->fddi_fc&FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
	    if (caplen < sizeof SNAPHDR+2) {
		tooshort++;
		return;
	    }
	    if (memcmp(p, SNAPHDR, sizeof SNAPHDR) == 0) {
		ether_type = GETNETSHORT(p+sizeof SNAPHDR);
		if (ether_type == 0x0800) {
		    caplen -= (sizeof SNAPHDR+2);
		    length -= (sizeof SNAPHDR+2);
		    p += (sizeof SNAPHDR+2);
		    p = dumpip(p, caplen, length);
		} else {
		    uncoded++;
		    return;
		}
	    } else {
		uncoded++;
		return;
	    }
	} else {
	    uncoded++;
	    return;
	}
	break;
    case DLT_NULL:
	if (caplen < NULL_HDRLEN) {
	    tooshort++;
	    return;
	}
	length -= NULL_HDRLEN;
	p += NULL_HDRLEN;
	caplen -= NULL_HDRLEN;
	p = dumpip(p, caplen, length);
	break;
    default:
	fprintf(stderr, "unknown DLT %d\n", pcap_dlt);
	exit(1);
    }

    /* (now, save [packetp, p) (half-open)] */

    if (p != packetp) {
	h->caplen = p-packetp;
	pcap_dump(user, h, packetp);
	pktsout++;
    }
}

/*
 *    I   N   I   T   I   A   L   I   Z   A   T   I   O   N
 *
 *                         A   N   D
 *
 *                       M   A   I   N
 */

int
dlt_hdrlen(int dlt)
{
    switch (dlt) {
    case DLT_EN10MB:
	return sizeof (struct ether_header);
    case DLT_SLIP:
	return SLIP_HDRLEN;
    case DLT_PPP:
	return PPP_HDRLEN;
#if	defined(FDDI_HDRLEN)
    case DLT_FDDI:
	return FDDI_HDRLEN;
#endif	/* defined(FDDI_HDRLEN) */
    case DLT_NULL:
	return NULL_HDRLEN;
    default:
	fprintf(stderr, "unknown DLT %d\n", dlt);
	exit(1);
    }
}

static void usage(char *cmd);
static void
verify_and_print_args(char *cmd)
{

    lookup_init(&addr_propagate);

    lookup_init(&addr_whole);

    lookup_init(&addr_upper);
    lookup_init(&addr_lower);

    lookup_init(&addr_byte_0);
    lookup_init(&addr_byte_1);
    lookup_init(&addr_byte_2);
    lookup_init(&addr_byte_3);

    tcpport_whole.flags = NH_FL_COUNTER;
    lookup_init(&tcpport_whole);

    tcpport_byte_0.flags = tcpport_byte_1.flags = NH_FL_COUNTER;
    lookup_init(&tcpport_byte_0);
    lookup_init(&tcpport_byte_1);

    udpport_whole.flags = NH_FL_COUNTER;
    lookup_init(&udpport_whole);

    udpport_byte_0.flags = udpport_byte_1.flags = NH_FL_COUNTER;
    lookup_init(&udpport_byte_0);
    lookup_init(&udpport_byte_1);

    switch (opt_ipaddr) {
    case 0:
	if (!qflag) {
	    fprintf(stderr,
		"# map 32-bit addresses into sequential integers\n");
	}
	break;
    case 1:
	if (!qflag) {
	    fprintf(stderr,
		"# map 16-bit address chunks into sequential integers\n");
	}
	break;
    case 2:
	if (!qflag) {
	    fprintf(stderr,
		"# map 8-bit address chunks into sequential integers\n");
	}
	break;
    case 50:
	if (!qflag) {
	    fprintf(stderr,
		"# map address using random numbers, "
		"preserving common prefix attributes\n");
	}
	break;
    case 99:
	if (qflag < 3) {
	    fprintf(stderr,
		"# WARNING WARNING WARNING WARNING WARNING WARNING WARNING\n");
	    fprintf(stderr,
		"# IP addresses being passed through without modification\n");
	    fprintf(stderr,
		"# WARNING WARNING WARNING WARNING WARNING WARNING WARNING\n");
	}
	break;
    default:
	fprintf(stderr, "unknown value %d for -A argument\n", opt_ipaddr);
	usage(cmd);
	/*NOTREACHED*/
    }

    if ((opt_class < 0) || ((opt_class > 32) && (opt_class != 99))) {
	fprintf(stderr, "invalid value %d for -C flag (s/b in range 0-32)\n",
				opt_class);
	usage(cmd);
	/*NOTREACHED*/
    }
    if (opt_class == 99) {
	opt_class = 32;
    }

#if	0
    /* XXX someday */
    switch (opt_linkaddr) {
    case 0:
	fprintf(stderr, "# remove linklayer information\n");
	break;
    case 99:
	fprintf(stderr, "# retain all linklayer information\n");
	break;
    default:
	fprintf(stderr, "unknown value %d for -L argument\n", opt_linkaddr);
	usage(cmd);
	/*NOTREACHED*/
    }
#endif	/* 0 */

    switch (opt_mcastaddr) {
    case 0:
	if (!qflag) {
	    fprintf(stderr,
		    "# multicast addresses cloaked per -A and -C flags\n");
	}
	break;
    case MCAST_OPT_NODE_LOCAL:
	if (!qflag) {
	    fprintf(stderr,
		"# multicast addressses in datagrams scoped node-local\n");
	    fprintf(stderr, "#\t(%d <= ttl <= %d) passed through unchanged\n",
				    optTOttlLOW(MCAST_OPT_NODE_LOCAL),
				    optTOttlHIGH(MCAST_OPT_NODE_LOCAL));
	}
    case MCAST_OPT_LINK_LOCAL:
	if (!qflag) {
	    fprintf(stderr,
		"# multicast addressses in datagrams scoped link-local\n");
	    fprintf(stderr, "#\t(%d <= ttl <= %d) passed through unchanged\n",
				    optTOttlLOW(MCAST_OPT_LINK_LOCAL),
				    optTOttlHIGH(MCAST_OPT_LINK_LOCAL));
	}
    case MCAST_OPT_SITE_LOCAL:
	if (!qflag) {
	    fprintf(stderr,
		"# multicast addressses in datagrams scoped site-local\n");
	    fprintf(stderr, "#\t(%d <= ttl <= %d) passed through unchanged\n",
				    optTOttlLOW(MCAST_OPT_SITE_LOCAL),
				    optTOttlHIGH(MCAST_OPT_SITE_LOCAL));
	}
    case MCAST_OPT_CONTINENT_LOCAL:
	if (!qflag) {
	    fprintf(stderr,
		"# multicast addressses in datagrams scoped continent-local\n");
	    fprintf(stderr, "#\t(%d <= ttl <= %d) passed through unchanged\n",
				    optTOttlLOW(MCAST_OPT_CONTINENT_LOCAL),
				    optTOttlHIGH(MCAST_OPT_CONTINENT_LOCAL));
	}
    case MCAST_OPT_GLOBAL:
	if (!qflag) {
	    fprintf(stderr,
		"# multicast addressses in datagrams scoped global\n");
	    fprintf(stderr, "#\t(%d <= ttl <= %d) passed through unchanged\n",
				    optTOttlLOW(MCAST_OPT_GLOBAL),
				    optTOttlHIGH(MCAST_OPT_GLOBAL));
	}
	break;
    case 99:
	if (!qflag) {
	    fprintf(stderr, "# multicast addresses passed through unchanged\n");
	}
	break;
    default:
	fprintf(stderr, "unknown value %d for -M argument\n", opt_mcastaddr);
	usage(cmd);
	/*NOTREACHED*/
    }

    switch (opt_tcpports) {
    case 0:
	if (!qflag) {
	    fprintf(stderr,
		"# map 16-bit TCP port numbers into sequential integer\n");
	}
	break;
    case 1:
	if (!qflag) {
	    fprintf(stderr,
	       "# map 8-bit TCP port number chunks into sequential integers\n");
	}
	break;
    case 99:
	if (!qflag) {
	    fprintf(stderr, "# pass TCP port numbers through unchanged\n");
	}
	break;
    default:
	fprintf(stderr, "unknown value %d for -T or -P argument\n",
								opt_tcpports);
	usage(cmd);
	/*NOTREACHED*/
    }

    switch (opt_udpports) {
    case 0:
	if (!qflag) {
	    fprintf(stderr,
		"# map 16-bit UDP port numbers into sequential integer\n");
	}
	break;
    case 1:
	if (!qflag) {
	    fprintf(stderr,
	       "# map 8-bit UDP port number chunks into sequential integers\n");
	}
	break;
    case 99:
	if (!qflag) {
	    fprintf(stderr, "# pass UDP port numbers through unchanged\n");
	}
	break;
    default:
	fprintf(stderr, "unknown value %d for -U or -P argument\n",
								opt_udpports);
	usage(cmd);
	/*NOTREACHED*/
    }
}



/*
 * print trailer statistics
 */

void
laststats(void)
{
    struct pcap_stat stat;

    if (!qflag) {
	/* Can't print the summary if reading from a savefile */
	if (pc != NULL && pcap_file(pc) == NULL) {
	    (void)fflush(stdout);
	    putc('\n', stderr);
	    if (pcap_stats(pc, &stat) < 0) {
		(void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pc));
	    } else {
		(void)fprintf(stderr, "# %d packets received by filter\n",
		    stat.ps_recv);
		(void)fprintf(stderr, "# %d packets dropped by kernel\n",
		    stat.ps_drop);
	    }
	}
	fprintf(stderr, "# pktsin %d pktsout %d tooshort %d uncoded %d\n",
			    pktsin, pktsout, tooshort, uncoded);
    }
}

/* make a clean exit on interrupts */
void
cleanup(int signo)
{
    laststats();
    exit(0);
}

static void
usage(char *cmd)
{
    fprintf(stderr,
	"usage:\n%s [-Opq] [-a [[hh:]mm:]ss] [-A {0|1|2|50|99}] [-c count]"
	"\n\t\t[-C {0|1|2|3|4|...|32|99}] [-F file] [-i interface]"
	"\n\t\t[-M {0|10|20|70|80|90|99}] [-{P|T|U} {0|1|99}] [-r file]"
	"\n\t\t[-s snaplen] [-w outputfile] [expression]\n", cmd);
    fprintf(stderr, "(one reasonable choice:  %s -P99 -C4 -M20 ...)\n", cmd);
    exit(1);
}

int
main(int argc, char *argv[], char *envp[])
{
    void local_bpf_dump(FILE *output, struct bpf_program *, int);
    char *copy_argv(register char **argv);
    char *read_infile(char *fname);
    char *rfile, *wfile;
    char *pgmfile, *interface;
    char *cmd = argv[0], *pgmbuf;
    char *alarm = 0;
    extern char *optarg;
    int ch, hdrlen, snaplen = 68;
    int pflag, Oflag, dflag;
    int count = -1;			/* default: all the packets */
    pcap_dumper_t *dc;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;
    bpf_u_int32 netmask, localnet;

    rand_start();

    /* parse arguments */
    wfile = "-";
    rfile = 0;
    pgmfile = 0;
    interface = 0;
    dflag = 0;
    pflag = 0;
    Oflag = 0;
    while ((ch = getopt(argc, argv, "a:A:c:C:dF:i:M:OpP:qr:s:S:T:U:w:")) != EOF) {
	switch (ch) {
	case 'a':
	    alarm = optarg;
	    break;
	case 'A':
	    opt_ipaddr = atoi(optarg);
	    break;
	case 'c':
	    count = atoi(optarg);
	    break;
	case 'C':
	    opt_class = atoi(optarg);
	    break;
	case 'd':
	    dflag++;
	    break;
	case 'F':
	    pgmfile = optarg;
	    break;
	case 'i':
	    interface = optarg;
	    break;
	case 'M':
	    opt_mcastaddr = atoi(optarg);
	    break;
	case 'O':
	    Oflag = 1;
	    break;
	case 'p':
	    pflag = 1;
	    break;
	case 'P':
	    opt_tcpports = opt_udpports = atoi(optarg);
	    break;
	case 'q':
	    qflag++;
	    break;
	case 'r':
	    rfile = optarg;
	    break;
	case 's':
	    snaplen = atoi(optarg);
	    break;
	case 'S':
	    opt_options = atoi(optarg);
	    break;
	case 'T':
	    opt_tcpports = atoi(optarg);
	    break;
	case 'U':
	    opt_udpports = atoi(optarg);
	    break;
	case 'w':
	    wfile = optarg;
	    break;
	default:
	    usage(cmd);
	    /*NOTREACHED*/
	}
    }

    /* if -r, open offline; else, set up live capture */
    if (rfile != 0) {
	if ((rfile[0] == '-') && (rfile[1] == 0)) {
	    if (isatty(0)) {
		fprintf(stderr, "attempt to read binary dump file from tty\n");
		usage(cmd);
		/*NOTREACHED*/
	    }
	}
	fddipad = FDDIPAD;	/* XXX -- what is this??? */
	pc = pcap_open_offline(rfile, pcap_errbuf);
	if (pc == NULL) {
	    fprintf(stderr, "%s\n", pcap_errbuf);
	    exit(2);
	}
	netmask = 0;
    } else {
	if (interface == 0) {
	    // interface = pcap_lookupdev(pcap_errbuf);
	    interface = pcap_lookupdev(pcap_errbuf);
	    if (interface == NULL) {
		fprintf(stderr, "%s\n", pcap_errbuf);
		exit(2);
	    }
	}
	pc = pcap_open_live(interface, snaplen, !pflag, 1000, pcap_errbuf);
	if (pc == NULL) {
	    fprintf(stderr, "%s\n", pcap_errbuf);
	    exit(2);
	}
	if (pcap_lookupnet(interface, &localnet, &netmask, pcap_errbuf) < 0) {
	    fprintf(stderr, "%s\n", pcap_errbuf);
	    exit(2);
	}
    }

    /* find filter expression */
    if (pgmfile) {
	pgmbuf = read_infile(pgmfile);
    } else {
	pgmbuf = copy_argv(&argv[optind]);
    }

    /* compile filter */
    if (pcap_compile(pc, &fcode, pgmbuf, Oflag, netmask) < 0) {
	fprintf(stderr, "%s\n", pcap_geterr(pc));
	exit(2);
    }

    /* dump? */
    if (dflag) {
	local_bpf_dump(stderr, &fcode, dflag);
	exit(0);
    }

    /* install filter */
    if (pcap_setfilter(pc, &fcode) < 0) {
	fprintf(stderr, pcap_geterr(pc));
	exit(2);
    }

    /* protect user's terminal... */
    if ((wfile[0] == '-') && (wfile[1] == 0)) {
	if (isatty(1)) {
	    fprintf(stderr, "attempt to write binary dump file to tty\n");
	    usage(cmd);
	    /*NOTREACHED*/
	}
    }

    /* set up output file */
    dc = pcap_dump_open(pc, wfile);
    if (dc == NULL) {
	fprintf(stderr, "%s\n", pcap_errbuf);
	exit(2);
    }

    /* lots of ways to stop (aside from EOF)...*/
    (void)signal(SIGTERM, cleanup);
    (void)signal(SIGINT, cleanup);
    (void)signal(SIGHUP, cleanup);
    (void)signal(SIGALRM, cleanup);

    pcap_dlt = pcap_datalink(pc);
    pcap_snap = pcap_snapshot(pc);

    hdrlen = dlt_hdrlen(pcap_dlt);
    pktbuffer = malloc(pcap_snap+4);		/* buffer space */
    switch (hdrlen&3) {				/* align IP header */
    case 0:
	break;
    case 1:
	pktbuffer += 3;
	break;
    case 2:
	pktbuffer += 2;
	break;
    case 3:
	pktbuffer += 1;
	break;
    }

    verify_and_print_args(cmd);

    if (alarm) {			/* if a duration ... */
	setalarm(alarm);
    }

    if (pcap_loop(pc, count, dumper, (u_char *)dc) < 0) {
	fprintf(stderr, "%s: pcap_loop: %s\n", cmd, pcap_geterr(pc));
	exit(2);
    }
    pcap_close(pc);
    pc = NULL;
    pcap_dump_close(dc);

    laststats();

    return 0;
}
