#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include "Anon.h"
#include "Hash.h"
#include "IP.h"
#include "TCP.h"
#include "UDP.h"
#include "ICMP.h"

namespace tcpmkpub {

u_short ip_checksum(Packet *pkt)
	{
	if ( ! pkt->IPHeader() )
		{
		Alert("incomplete IP header for IP checksum computation");
		return 0;
		}

	return 0xffff - ones_complement_checksum(
		(const void *) pkt->IPHeader(), 
		pkt->IPHdrLen());
	}

DATA_PROCESSOR(recompute_ip_checksum)
	{
	u_short input_checksum = ip_checksum(pkt_in);
	u_short new_chksum = ip_checksum(pkt_out);

	if ( ! pkt_in->IPHeader() )
		{
		Export(PER_PACKET, 
			"unverifiable checksum",
			"incomplete %sIP header",
			pkt_in->is_embedded_pkt() ? "(embedded) " : "");
		}

	if ( input_checksum != 0 )
		{
		report_checksum_error("IP", pkt_in, pkt_out, 
			pkt_in->IPChkSum(), input_checksum);
		// Mark the new checksum
		new_chksum = make_incorrect_checksum(new_chksum);
		}

	if ( pkt_in->IPChkSum() == 0xffff )
		Alert("illegal IP checksum: 0xffff");

	pkt_out->dump((const u_char *) &new_chksum, 2, offset_out);
	offset_in += 2;
	offset_out += 2;
	}

DATA_PROCESSOR(anonymize_ip_pkt)
	{
	pkt_in->PushNetHeader(offset_in);
	pkt_out->PushNetHeader(offset_out);

#	include "field.macros"
#	include "policy/ip.anon"

	pkt_in->PopNetHeader();
	pkt_out->PopNetHeader();
	}

DATA_PROCESSOR(anonymize_ip_options)
	{
	int ip_option_end = 
		offset_in + 
		check_data_length(pkt_in, "IP options", 
		                  offset_in, pkt_in->IPOptionLen(), caplen);

	while ( offset_in < ip_option_end )
		{
		int ip_option_type = start[offset_in];

		if ( ip_option_type <= 1 || offset_in + 1 >= caplen )
			len = 1;
		else
			len = start[offset_in + 1];

		DebugMsg("processing IP option %d:%d", ip_option_type, len);

		switch ( ip_option_type )
			{
#			include "case.macros"
#			include "policy/ip-option.anon"
			}
		}

	if ( offset_in != offset_out )
		{
		Alert("IP header length changes: %d != %d", 
		      offset_in, offset_out);
		}
	}

DATA_PROCESSOR(anonymize_ip_data)
	{
	len = pkt_in->IPPayloadLen();

	if ( offset_in + len > caplen )
		{
		pkt_in->CheckTruncation(data_name, 
		                        offset_in, len, caplen, 
		                        true);
		len = caplen - offset_in;
		}

	if ( pkt_in->IPFragOffset() > 0 )
		{
#		include "field.macros"
#		include "policy/ip-frag.anon"
		return;
		}

	pkt_in->PushTransportHeader(offset_in);
	pkt_out->PushTransportHeader(offset_out);
	switch ( pkt_in->IPProto() )
		{
#		include "case.macros"
#		include "policy/ip-data.anon"
		}
	pkt_in->PopTransportHeader();
	pkt_out->PopTransportHeader();
	}

DATA_PROCESSOR(IPOPT_anonymize_record_route)
	{
	int opt_end = offset_in + len;
	if ( opt_end > caplen )
		opt_end = caplen;
	
	int rr_end;
	if ( offset_in + 2 >= opt_end )
		{
		Alert("incomplete IP option");
		rr_end = opt_end;
		}
	else
		{
		rr_end = offset_in + start[offset_in + 2];
		if ( rr_end > opt_end )
			rr_end = opt_end;
		}

	// Copy <type, len, pointer>
	Copy(data_name, start, caplen, 
		offset_in, 3, offset_out, pkt_in, pkt_out);

	while ( offset_in + 4 <= rr_end )
		{
		anonymize_ip_addr(data_name, 
			start, caplen, offset_in, 4, offset_out,
			pkt_in, pkt_out);
		} 

	len = opt_end - offset_in;
	// Fill rest of data with 0
	if ( len > 0 )
		ZERO_IT;
	}

DATA_PROCESSOR(IPOPT_alert_and_replace_with_NOP)
	{
	u_char ip_option_type = start[offset_in];
	Alert("unexpected IP option: %d", ip_option_type); 
	// Replace with NOP
	if ( offset_in + len > caplen )
		{
		// Should never occur because len will always be checked
		internal_error("truncated IP option: %d", ip_option_type);
		len = caplen - offset_in;
		}
	pkt_out->dump(IPOPT_NOP, len, offset_out);
	offset_in += len;
	offset_out += len;
	}

}  // namespace tcpmkpub

