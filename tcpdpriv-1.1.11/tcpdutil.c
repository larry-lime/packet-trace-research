/* from tcpdump/bpf_dump.c and extracts from tcpdump/util.c ... */

/*
 * Copyright (c) 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
#ifndef lint
static char rcsid[] =
    "@(#) $Header: /usr/home/minshall/src/mine/tcpdpriv/RCS/tcpdutil.c,v 1.6 1997/08/28 00:03:04 minshall Exp $ (LBL)";
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include <pcap.h>

/*
 * deal with systems in which bpf_int32 and bpf_u_int32 are not defined
 */
#if ((PCAP_VERSION_MAJOR < 2) || (PCAP_VERSION_MINOR < 4))
typedef int bpf_int32;
typedef u_int bpf_u_int32;
#endif /* ((PCAP_VERSION_MAJOR < 2) || (PCAP_VERSION_MINOR < 4)) */


    /* macros for ansi/non-ansi compatibility */
#ifndef __P
#if defined(_USE_PROTOTYPES) && (defined(__STDC__) || defined(__cplusplus))
#define	__P(protos)	protos		/* full-blown ANSI C */
#else
#define	__P(protos)	()		/* traditional C preprocessor */
#endif
#endif

#if	defined(sun) && !defined(SVR4)
int	fprintf __P((FILE *, const char *, ...));
int 	fputs __P((char *s, FILE *stream));
#endif	/* defined(sun) && !defined(SVR4) */

/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */

char *
copy_argv(register char **argv)
{
    register char **p;
    register int len = 0;
    char *buf;
    char *src, *dst;

    p = argv;
    if (*p == 0) {
	return 0;
    }

    while (*p) {
	len += strlen(*p++) + 1;
    }

    buf = (char *)malloc(len);

    if (buf == 0) {
	fprintf(stderr, "no room for argument string (%d bytes) in %s:%d\n",
			    len, __FILE__, __LINE__);
	exit(2);
    }

    p = argv;
    dst = buf;
    while ((src = *p++) != NULL) {
	while ((*dst++ = *src++) != '\0') {
	    ;
	}
	dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}


/*
 * Copy the contents of a file into an in-memory buffer.
 */

char *
read_infile(char *fname)
{
    struct stat buf;
    int fd;
    char *p;

    fd = open(fname, O_RDONLY);
    if (fd < 0) {
	fprintf(stderr, "can't open '%s'", fname);
	exit(2);
    }

    if (fstat(fd, &buf) < 0) {
	fprintf(stderr, "can't state '%s'", fname);
	exit(2);
    }

    p = (char *)malloc((u_int)buf.st_size);

    if (p == 0) {
	fprintf(stderr, "no room for argument string (%d bytes) in %s:%d\n",
			    (int) buf.st_size, __FILE__, __LINE__);
	exit(2);
    }

    if (read(fd, p, (int)buf.st_size) != buf.st_size) {
	fprintf(stderr, "problem reading '%s'", fname);
	exit(2);
    }

    return p;
}



void
local_bpf_dump(FILE *output, struct bpf_program *p, int option)
{
	struct bpf_insn *insn;
	int i;
	int n = p->bf_len;

	insn = p->bf_insns;
	if (option > 2) {
		fprintf(output, "%d\n", n);
		for (i = 0; i < n; ++insn, ++i) {
			fprintf(output, "%u %u %u %u\n", insn->code,
			       insn->jt, insn->jf, insn->k);
		}
		return ;
	}
	if (option > 1) {
		for (i = 0; i < n; ++insn, ++i)
			fprintf(output, "{ 0x%x, %d, %d, 0x%08x },\n",
			       insn->code, insn->jt, insn->jf, insn->k);
		return;
	}
	for (i = 0; i < n; ++insn, ++i) {
#ifdef BDEBUG
		extern int bids[];
		fprintf(output, bids[i] > 0 ? "[%02d]" : " -- ", bids[i] - 1);
#endif
		fputs(bpf_image(insn, i), output);
		fputs("\n", output);
	}
}
