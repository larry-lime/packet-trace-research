/****************************************************************************
 * 
 * tcpurify - capture.h
 * 
 * This program is Copyright 2000, 2001 by Ethan Blanton; please see the
 * accompanying copy of the GNU General Public License for your rights
 * regarding the usage and distribution of this software.
 * 
 ***************************************************************************/

#ifndef CAPTURE_H
#define CAPTURE_H

#include <sys/types.h>
#include <pcap.h>

void capture_cb(u_char *data, const struct pcap_pkthdr *ph, const u_char *pkt);
void timed_cb(u_char *data, const struct pcap_pkthdr *ph, const u_char *pkt);

#endif /* CAPTURE_H */
