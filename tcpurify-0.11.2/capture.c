/****************************************************************************
 * 
 * tcpurify - capture.c
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

/* I have to have this on Linux for some reason */
#define _BSD_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "tcpurify.h"
#include "timeval.h"

/* It seems that some systems (DEC UNIX, to my knowledge) don't define this */
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP 0x8035
#endif

enum {
  CSUM_OK,
  CSUM_BAD,
  CSUM_INVAL
};

/*
 * This is our typical capture function that sanitizes the packets as
 * they go through...  We don't use the u_char *data field as of yet,
 * although I must admit I'm kicking some plans for it around in my head.
 * Don't use it just yet...
 */
void capture_cb(u_char *data, const struct pcap_pkthdr *cph, const u_char *cpkt)
{
  /* 
   * I would like to put in record that I *did not* want to change constant
   * pointers...  This is Dr. Ostermann's fault.  ;-)
   */

  struct pcap_pkthdr *ph = (struct pcap_pkthdr *)cph;
  u_char *pkt = (u_char *)cpkt;
  
  struct ether_header *eh;
  struct ip *iph;
  struct udphdr *udph;
  struct tcphdr *tcph;
  uint16_t source, dest, tcplen;
  u_char *cur;
  uint32_t delta, i, sum;
  uint16_t *adjust;
  int len;
  
  len = sizeof (struct ether_header);
  if (ph->caplen < len) { /* short packet, don't deal with it */
    return;
  }
  eh = (struct ether_header *)pkt;
  cur = pkt + sizeof(struct ether_header);
  switch(ntohs(eh->ether_type)) {
   case ETHERTYPE_IP:
    if (ph->caplen < (len += sizeof(struct ip))) return;
    iph = (struct ip *)(pkt + sizeof(struct ether_header));
    delta = 0xffff0000;
    adjust = (uint16_t *)&iph->ip_src.s_addr;
    for (i = 0; i < 4; i++) {
      delta -= ntohs (*(adjust + i));
    }
    while (delta >> 16) {
      delta = (delta >> 16) + (delta & 0xffff);
    }
    if (config.reverse) {
      (*config.enc->decode) (&iph->ip_src.s_addr);
      (*config.enc->decode) (&iph->ip_dst.s_addr);
    } else {
      (*config.enc->encode) (&iph->ip_src.s_addr);
      (*config.enc->encode) (&iph->ip_dst.s_addr);
    }
    adjust = (uint16_t *)&iph->ip_src.s_addr;
    for (i = 0; i < 4; i++) {
      delta += ntohs (*(adjust + i));
    }
    /* Solaris on a SPARC returns incorrect values if we don't mask this to
     * sixteen bits...  I'm not sure why */
    sum = ntohs ((uint16_t)~iph->ip_sum) + delta;
    while (sum >> 16) {
      sum = (sum >> 16) + (sum & 0xffff);
    }
    iph->ip_sum = htons ((uint16_t)~sum);
    cur += 4 * iph->ip_hl;
    if(config.truncate) {
      switch(iph->ip_p) {
       case IPPROTO_UDP:
        if (ph->caplen < (len += sizeof(struct udphdr))) return;
	udph = (struct udphdr *)cur;
	cur += sizeof(struct udphdr);
	source = ntohs(udph->uh_sport);
	dest = ntohs(udph->uh_dport);
	
	if (udph->uh_sum) {
	  sum = (0xffff & ntohs (~udph->uh_sum)) + delta;
	  while (sum >> 16) {
	    sum = (sum >> 16) + (sum & 0xffff);
	  }
	  if ((sum & 0xffff) == 0xffff) {
	    sum = 0;
	  }
	  udph->uh_sum = htons ((uint16_t)~sum);
	}
	
	/* These are ports we consider 'safe', so leave 'em alone */
	if((source == 7) || (dest == 7) ||	/* echo			*/
	   (source == 9) || (dest == 9) ||	/* discard		*/
	   (source == 13) || (dest == 13) ||	/* daytime		*/
	   (source == 19) || (dest == 19) ||	/* chargen		*/
	   (source == 37) || (dest == 37) ||	/* time 		*/
	   /* (source == 9) || (dest == 9) || *//* dns - I disagree here*/
	   (source == 67) || (dest == 67) ||	/* bootps		*/
	   (source == 68) || (dest == 68) ||	/* bootpc		*/
   	   /*(source == 79) || (dest == 79) ||*//* finger -- here, too	*/
	   (source == 520) || (dest == 520)) {	/* routed		*/
	} else {
	  /* These are *not* safe, or are unknown
	   * 
	   * zero out the first 4 bytes, as we suspect pcap might leave 
	   * them in if we're not careful. */
	  memset(cur, '\0', (ph->caplen - (cur - pkt) < 4)
		 ? (ph->caplen - (cur - pkt)) : 4);
	  ph->caplen = (cur - pkt);
	}
	break;
       case IPPROTO_TCP:
        if (ph->caplen < (len += sizeof(struct tcphdr))) return;
	tcph = (struct tcphdr *)cur;
	cur += 4 * tcph->th_off;
	source = ntohs(tcph->th_sport);
	dest = ntohs(tcph->th_dport);
	
	sum = (0xffff & ntohs (~tcph->th_sum)) + delta;
	while (sum >> 16) {
	  sum = (sum >> 16) + (sum & 0xffff);
	}
	tcph->th_sum = htons ((uint16_t)~sum);

        if(config.verify_cs) {
          tcplen = ntohs(iph->ip_len) - (iph->ip_hl << 2);
          if (ph->caplen < len + tcplen - sizeof(struct tcphdr)) {
            tcph->th_sum = htons(CSUM_INVAL);
          } else {
            sum = 0;
            for(i = 0; i < 4; i++) {
              sum += *((uint16_t *)(&iph->ip_src.s_addr) + i);
            }
            sum += htons(iph->ip_p);
            sum += htons(tcplen);
            for(i = 0; i < (tcplen >> 1); i++) {
              sum += *((uint16_t *)tcph + i);
            }
            if(tcplen % 2) {
              sum += *((uint8_t *)tcph + tcplen - 1);
            }
            while(sum & 0xffff0000) {
              sum = (sum >> 16) + (sum & 0xffff);
            }
            tcph->th_sum = htons(sum == 0xffff ? CSUM_OK : CSUM_BAD);
          }
        }
	
	/* These are ports we consider 'safe', so leave 'em alone */
	if((source == 7) || (dest == 7) ||	/* echo			*/
	   (source == 9) || (dest == 9) ||	/* discard		*/
	   (source == 13) || (dest == 13) ||	/* daytime		*/
	   (source == 19) || (dest == 19) ||	/* chargen		*/
	   (source == 37) || (dest == 37) ||	/* time			*/
	   /* (source == 9) || (dest == 9) || *//* dns - I disagree here*/
	   (source == 67) || (dest == 67) ||	/* bootps		*/
	   (source == 68) || (dest == 68) ||	/* bootpc		*/
	   /*(source == 79) || (dest == 79) ||*//* finger -- here, too	*/
	   (source == 520) || (dest == 520)) {	/* routed		*/
	} else {
          /* These are *not* safe, or are unknown */
          if ((cur - pkt) < ph->caplen) {
            /* in this case, the captured packet extends beyond the TCP
             * header and TCP options and we want to truncate all of the
             * 'unsafe' data */
            /* zero out the first 4 bytes, as we suspect pcap might leave 
             * them in if we're not careful. */
            memset(cur, '\0', (ph->caplen - (cur - pkt) < 4)
                   ? (ph->caplen - (cur - pkt)) : 4);
            ph->caplen = (cur - pkt);
          } else {
            /* bugfix: in this case, the entire TCP header is present, but
             * the packet was truncated (i.e. by a short snap length)
             * somewhere in the middle of the TCP options, so we shouldn't
             * take further action */
          }
	  
          /* And fix the checksum, just in case */
          /* OK, here's the story -- for *very* small TCP packets, I'm
	   * pretty sure the checksum can be exploited to reconstruct
	   * most (all on 2-byte packets) of the contents of the packet;
	   * however, zeroing the checksum makes the traces less useful
	   * for intrusion detection purposes.
	   * 
	   * The bottom line here is that if you're using telnet (which is
	   * pretty much the only thing I can think of that generates lots
	   * of very small packets that might contain sensitive data) you
	   * deserve what you get anyway, so I'm leaving the checksum
	   * in.  :-) */
	  /* tcph->th_sum = 0x0; */
	}
	break;
       case IPPROTO_ICMP:
	/* This probably contains an IP header, which would be unsanitized ...
	 * The ideal thing to do is truncate after the ICMP header, but at
	 * this point I'm going to truncate after IP. */
	break;
       default:
	/* I don't know what this is, be paranoid and truncate it after the 
	 * IP header */
	if(config.truncate) {
	  memset(cur, '\0', (ph->caplen - (cur - pkt) < 4)
		 ? (ph->caplen - (cur - pkt)) : 4);
	  ph->caplen = (cur - pkt);
	}
      }
    }
    break;
   case ETHERTYPE_ARP:
   case ETHERTYPE_REVARP:
    /* It wouldn't do much good to sanitize if we could retrieve the original
     * mappings from the MAC address, now would it? */
   default:
    /* I don't even know what protocol this is.  More paranoia tells us to
     * truncate it immediately after the Ethernet header */
    memset(cur, '\0', (ph->caplen - (cur - pkt) < 4)
                      ? (ph->caplen - (cur - pkt)) : 4);
    ph->caplen = (cur - pkt);
  }
  
  dump(ph, pkt);
}

/*
 * This guy does no sanitization, but attempts to throw the packets out with
 * a timing similar to how they originally arrived.  It's not the most
 * accurate timing, but it's what we've got.
 */
void timed_cb(u_char *data, const struct pcap_pkthdr *ph, const u_char *pkt)
{
  struct timeval now, tmp, delay;
  
  if(!times.virt.tv_sec) {
    times.virt.tv_sec = ph->ts.tv_sec;
    times.virt.tv_usec = ph->ts.tv_usec;
    if(tvgreater(&times.virt, &times.wall)) {
      fprintf(stderr, "tcpurify: packet capture time is later than wall clock time.\n");
      fprintf(stderr, "          Fix this and try again.\n");
      exit(1);
    }
    tvsub(&times.off, &times.wall, &times.virt);
    if(config.debug) {
      fprintf(stderr, "Offset: %lus, %luus\n", 
	      times.off.tv_sec, times.off.tv_usec);
    }
  }
  
  gettimeofday(&now, NULL);
  tvsub(&tmp, &now, &times.off);
  if(tvgreater((struct timeval *)&ph->ts, &tmp)) {
    tvsub(&delay, (struct timeval *)&ph->ts, &tmp);
    if(config.debug) {
      printf("Sleeping for %lu seconds, %lu microseconds\n", 
	     delay.tv_sec, delay.tv_usec);
    }
    if(config.maxtime &&
       ((delay.tv_sec * 1000 + delay.tv_usec / 1000) > config.maxtime))
    {
      usleep(config.maxtime * 1000);
    } else {		  
      usleep(delay.tv_sec * 1000000 + delay.tv_usec);
    }
  }
  dump(ph, pkt);
}
