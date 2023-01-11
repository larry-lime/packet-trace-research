#ifndef anon_h
#define anon_h

#include <stdarg.h>

#include "common.h"
#include "ConstChecker.h"
#include "DataProcessor.h"
#include "Packet.h"
#include "Special.h"
#include "TCPMkPub.h"

#include "DataProcessor-inl.h"

namespace tcpmkpub {

// - adapted from tcpdump
// Returns the ones-complement checksum of a chunk of b short-aligned bytes.
static inline unsigned int ones_complement_checksum(
		const void* p, int b, unsigned int sum = 0xffff)
        {
        const u_short* sp = (const u_short*) p;       // better be aligned!

	if ( b % 2 )
		{
		const u_char *bp = (const u_char *) p;
		u_char tmp[2] = {bp[b-1], 0};
		sum += *((u_short *) tmp);
		--b;
		}

        b /= 2; // convert to count of short's

        /* No need for endian conversions. */
        while ( --b >= 0 )
                sum += *sp++;

        while ( sum > 0xffff )
                sum = (sum & 0xffff) + (sum >> 16);

        return sum;
        }

static inline void report_checksum_error(const char *proto, 
		InputPacket *pkt_in, OutputPacket *pkt_out,
		u_short orig_sum, u_short sum_diff)
	{
	u_long correct_sum = (u_long) orig_sum + (u_long) sum_diff;
	while ( correct_sum > 0xffff )
		correct_sum = (correct_sum & 0xffff) + (correct_sum >> 16);
	if ( correct_sum == 0xffff )
		correct_sum = 0;
	Alert("bad %s checksum: %s orig: %04x diff: %04x, mask: %04x", 
		proto, pkt_in->FlowID().c_str(), 
		orig_sum, sum_diff, correct_sum ^ orig_sum);
	Export(PER_PACKET, "bad checksum", 
		"%s: %s", proto, pkt_out->FlowID().c_str());
	}

static inline u_short make_incorrect_checksum(u_short correct_checksum)
	{
	return correct_checksum == 1 ? 2 : 1;
	}

}  // namespace tcpmkpub

#endif /* anon_h */
