#include "Anon.h"
#include "ARP.h"
#include "Ethernet.h"
#include "IP.h"

namespace tcpmkpub {

DATA_PROCESSOR(anonymize_arp_pkt)
	{
	pkt_in->PushNetHeader(offset_in);
	pkt_out->PushNetHeader(offset_out);

#	include "field.macros"
#	include "policy/arp.anon"

	pkt_in->PopNetHeader();
	pkt_out->PopNetHeader();
	}

}  // namespace tcpmkpub
