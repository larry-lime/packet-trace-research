#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
// #include <netinet/udp.h>

#include "Anon.h"
#include "UDP.h"

namespace tcpmkpub {

DATA_PROCESSOR(anonymize_udp_pkt)
	{
	// fprintf(stderr, "UDP pkt: offset=%d,%d len=%d\n", 
	// 	offset_in, offset_out, len);

#	include "field.macros"
#	include "policy/udp.anon"

	// fprintf(stderr, "after UDP: offset=%d,%d len=%d\n", 
	// 	offset_in, offset_out, len);
	}

u_short udp_checksum(const Packet *pkt)
	{
	u_short chksum = 0xffff;

	const struct ip *iphdr = pkt->IPHeader();
	if ( ! iphdr )
		{
		Alert("incomplete %sIP header for UDP checksum computation",
			pkt->is_embedded_pkt() ? "(embedded) " : "");
		return 0;
		}

	const struct udphdr *udphdr = pkt->UDPHeader();
	if ( ! udphdr )
		{
		if ( ! pkt->is_embedded_pkt() )
			Alert("incomplete UDP header for checksum computation"); 
		return 0;
		}

	// The pseudo-header
	chksum = ones_complement_checksum(&(iphdr->ip_src), 4, chksum);
	chksum = ones_complement_checksum(&(iphdr->ip_dst), 4, chksum);
	u_short proto = htons(iphdr->ip_p);
	chksum = ones_complement_checksum(&proto, 2, chksum);
	u_short udplen = htons(pkt->IPPayloadLen());
	chksum = ones_complement_checksum(&udplen, 2, chksum);

	chksum = ones_complement_checksum(
		(const void *) udphdr, 
		pkt->TransportLen(),
		chksum);
	
	return 0xffff - chksum;
	}

u_short recompute_udp_checksum(InputPacket *pkt_in, OutputPacket *pkt_out)
	{
	if ( pkt_in->UDPChkSum() == 0 ) // UDP "no cksum"
		{
		if ( FLAGS_export_no_UDP_checksum )
			{
			Export(PER_PACKET, 
			       "no UDP checksum",
			       "%s",
			       pkt_out->FlowID().c_str());
			}
		return 0;
		}

	u_short new_chksum = udp_checksum(pkt_out);

	if ( pkt_in->is_fragmented() )
		{
		// ### Deficiency: cannot verify checksum for fragmented packets
		// Do nothing
		}
	else if ( pkt_in->TransportLen() == pkt_in->IPPayloadLen() )
		// Otherwise we cannot check whether the checksum is correct
		{
		u_short input_checksum = udp_checksum(pkt_in);
		if ( input_checksum != 0 )
			{
			report_checksum_error("UDP", pkt_in, pkt_out, 
				pkt_in->UDPChkSum(), input_checksum);
			// Mark the new checksum
			new_chksum = make_incorrect_checksum(new_chksum);
			}
		}
	else
		{
		// Do not generate the message if we know packets are truncated 
		if ( FLAGS_alert_on_packet_truncation )
			{
			Export(PER_PACKET, 
				"unverifiable checksum",
				"incomplete %sUDP data",
				pkt_in->is_embedded_pkt() ? "(embedded) " : "");
			}
		}

	if ( new_chksum == 0 )
		new_chksum = 0xffff;
	return new_chksum;
	}

DATA_PROCESSOR(recompute_udp_checksum)
	{
	u_short new_chksum = recompute_udp_checksum(pkt_in, pkt_out);
	pkt_out->dump((const u_char *) &new_chksum, 2, offset_out);
	offset_in += 2;
	offset_out += 2;
	}

}  // namespace tcpmkpub
