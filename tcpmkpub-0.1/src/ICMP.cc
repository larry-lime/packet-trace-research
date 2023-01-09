#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "Anon.h"
#include "ICMP.h"
#include "IP.h"

namespace tcpmkpub {

u_short icmp_checksum(const Packet *pkt)
	{
	const struct icmp *icmphdr = pkt->ICMPHeader();
	if ( ! icmphdr )
		{
		if ( ! pkt->is_embedded_pkt() )
			Alert("incomplete ICMP header for checksum computation");
		return 0;
		}

	return 0xffff - ones_complement_checksum(
		(const void *) icmphdr, 
		pkt->TransportLen());
	}

u_short recompute_icmp_checksum(InputPacket *pkt_in, OutputPacket *pkt_out)
	{
	u_short new_chksum = icmp_checksum(pkt_out);
	if ( pkt_in->is_fragmented() )
		{
		// ### Deficiency: cannot verify checksum for fragmented packets
		// Do nothing
		}
	else if ( pkt_in->TransportLen() == pkt_in->IPPayloadLen() )
		// Otherwise we cannot check if the checksum is correct
		{
		u_short input_checksum = icmp_checksum(pkt_in);
		if ( input_checksum != 0 )
			{
			report_checksum_error("ICMP", pkt_in, pkt_out, 
				pkt_in->ICMPChkSum(), input_checksum);
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
			       "incomplete %sICMP data",
			       pkt_in->is_embedded_pkt() ? "(embedded) " : "");
			}
		}

	return new_chksum;
	}

DATA_PROCESSOR(recompute_icmp_checksum)
	{
	if ( pkt_in->ICMPChkSum() == 0xffff )
		Alert("illegal ICMP checksum: 0xffff");

	u_short new_chksum = recompute_icmp_checksum(pkt_in, pkt_out);
	pkt_out->dump((const u_char *) &new_chksum, 2, offset_out);
	offset_in += 2;
	offset_out += 2;
	}

DATA_PROCESSOR(anonymize_icmp_pkt)
	{
#	include "field.macros"
#	include "policy/icmp.anon"
	}

DATA_PROCESSOR(anonymize_icmp_echo)
	{
#	include "field.macros"
#	include "policy/icmp-echo.anon"
	}

DATA_PROCESSOR(anonymize_icmp_tstamp)
	{
#	include "field.macros"
#	include "policy/icmp-tstamp.anon"
	}

DATA_PROCESSOR(anonymize_icmp_ireq)
	{
#	include "field.macros"
#	include "policy/icmp-ireq.anon"
	}

DATA_PROCESSOR(anonymize_icmp_maskreq)
	{
#	include "field.macros"
#	include "policy/icmp-maskreq.anon"
	}

DATA_PROCESSOR(anonymize_icmp_context)
	{
#	include "field.macros"
#	include "policy/icmp-context.anon"
	}

DATA_PROCESSOR(anonymize_icmp_redirect)
	{
#	include "field.macros"
#	include "policy/icmp-redirect.anon"
	}

DATA_PROCESSOR(anonymize_icmp_paramprob)
	{
#	include "field.macros"
#	include "policy/icmp-paramprob.anon"
	}

DATA_PROCESSOR(anonymize_icmp_routersolicit)
	{
#	include "field.macros"
#	include "policy/icmp-routersolicit.anon"
	}

DATA_PROCESSOR(ICMP_alert_and_skip)
	{
	Alert("%s unknown ICMP type %d", 
		pkt_in->FlowID().c_str(), pkt_in->ICMPType());
	SKIP_IT;
	}

DATA_PROCESSOR(anonymize_icmp_data)
	{
	switch ( pkt_in->ICMPType() )
		{
#		include "case.macros"
#		include "policy/icmp-data.anon"
		}
	}

}  // namespace tcpmkpub
