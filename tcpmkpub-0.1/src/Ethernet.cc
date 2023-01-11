#include <sys/types.h>
#include <net/ethernet.h>

#include "Anon.h"
#include "Ethernet.h"
#include "IP.h"
#include "ARP.h"

namespace tcpmkpub {

// Note: For packets with payload curtailed, we cannot keep the
// ethernet checksums. Then shall we really try to keep ethernet
// checksum for *some* packets? Or leave them out all together?
// Check policy/ether.anon.
DATA_PROCESSOR(recompute_ethernet_cheksum)
	{
	if ( offset_in == offset_out )
		ZERO_IT;
	else
		SKIP_IT;
	}

DATA_PROCESSOR(anonymize_ethernet_pkt)
	{
	pkt_in->SetEtherHeader(offset_in);
	pkt_out->SetEtherHeader(offset_out);

#	include "field.macros"
#	include "policy/ether.anon"
	}

DATA_PROCESSOR(other_ethertnet_pkt_alert_and_skip)
	{
	if ( FLAGS_alert_on_non_IP_pkts )
		Alert("non-IP packet %d", pkt_in->EtherType());
	SKIP_IT;
	}

DATA_PROCESSOR(anonymize_ethernet_data)
	{
	if ( len == VARLEN )
		len = caplen - offset_in;
	// fprintf(stderr, "ethernet data: offset=%d,%d len=%d\n", offset_in, offset_out, len);
	switch ( pkt_in->EtherType() )
		{
#		include "case.macros"
#		include "policy/ether-data.anon"
		}
	}

}  // namespace tcpmkpub
