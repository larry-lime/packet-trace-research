#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
// #include <netinet/tcp.h>

#include "Anon.h"
#include "TCP.h"

#include <set>
#include <vector>
#include <algorithm>
using namespace std;

namespace tcpmkpub {

u_short tcp_checksum(Packet *pkt)
	{
	u_short chksum = 0xffff;

	const struct ip *iphdr = pkt->IPHeader();
	if ( ! iphdr )
		{
		Alert("incomplete %sIP header for TCP checksum computation",
			pkt->is_embedded_pkt() ? "(embedded) " : "");
		return 0;
		}

	const struct tcphdr *tcphdr = pkt->TCPHeader();
	if ( ! tcphdr )
		{
		if ( ! pkt->is_embedded_pkt() )
			Alert("incomplete TCP header for checksum computation"); 
		return 0;
		}

	// The pseudo-header
	chksum = ones_complement_checksum(&(iphdr->ip_src), 4, chksum);
	chksum = ones_complement_checksum(&(iphdr->ip_dst), 4, chksum);
	u_short proto = htons(iphdr->ip_p);
	chksum = ones_complement_checksum(&proto, 2, chksum);
	u_short tcplen = htons(pkt->IPPayloadLen());
	chksum = ones_complement_checksum(&tcplen, 2, chksum);

	chksum = ones_complement_checksum(
		(const void *) tcphdr, 
		pkt->TransportLen(),
		chksum);

	return 0xffff - chksum;
	}

u_short recompute_tcp_checksum(InputPacket *pkt_in, OutputPacket *pkt_out)
	{
	u_short new_chksum = tcp_checksum(pkt_out);
	if ( pkt_in->is_fragmented() )
		{
		// ### Deficiency: cannot verify checksum for fragmented packets
		// Do nothing
		}
	else if ( pkt_in->TransportLen() == pkt_in->IPPayloadLen() )
		// Otherwise we cannot check if the checksum is correct
		{
		u_short input_checksum = tcp_checksum(pkt_in);
		if ( input_checksum != 0 )
			{
			report_checksum_error("TCP", pkt_in, pkt_out, 
				pkt_in->TCPChkSum(), input_checksum);
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
				"incomplete %sTCP data",
				pkt_in->is_embedded_pkt() ? "(embedded) " : "");
			}
		}

	return new_chksum;
	}

DATA_PROCESSOR(recompute_tcp_checksum)
	{
	u_short new_chksum = recompute_tcp_checksum(pkt_in, pkt_out);
	if ( pkt_in->TCPChkSum() == 0xffff )
		{
		Alert("illegal TCP checksum: 0xffff");
		if ( new_chksum == 0 )
			new_chksum = 0xffff;
		}

	pkt_out->dump((const u_char *) &new_chksum, 2, offset_out);
	offset_in += 2;
	offset_out += 2;
	}

DATA_PROCESSOR(anonymize_tcp_pkt)
	{
	// fprintf(stderr, "TCP pkt: offset=%d,%d len=%d\n", offset_in, offset_out, len);
#	include "field.macros"
#	include "policy/tcp.anon"
	}

DATA_PROCESSOR(anonymize_tcp_options)
	{
	int tcp_option_end = offset_in + check_data_length(pkt_in, "TCP options", 
				offset_in, pkt_in->TCPOptionLen(), caplen);

	while ( offset_in < tcp_option_end )
		{
		int tcp_option_type = start[offset_in];


		if ( tcp_option_type <= 1 || offset_in + 1 >= caplen )
			len = 1;
		else
			len = start[offset_in + 1];

		switch ( tcp_option_type )
			{
#			include "case.macros"
#			include "policy/tcp-option.anon"
			}
		}
	}

DATA_PROCESSOR(TCPOPT_alert_and_replace_with_NOP)
	{
	u_char tcp_option_type = start[offset_in];
	Alert("unexpected TCP option: %d", tcp_option_type); 
	// Replace with NOP
	if ( offset_in + len > caplen )
		{
		// Should never occur because len will always be checked
		internal_error("truncated TCP option: %d", tcp_option_type);
		len = caplen - offset_in;
		}
	pkt_out->dump(TCPOPT_NOP, len, offset_out);
	offset_in += len;
	offset_out += len;
	}

DATA_PROCESSOR(note_tcpopt_ts)
	{
	Note("TCP option timestamp: %s len=%d", 
		pkt_in->FlowID().c_str(), len);
	COPY_IT;
	}


///////////////////////////////////////////////////////////
// The following code deals with TCP timestamp options

static int num_tcp_timestamps = 0;	// counting only the distinct ones

typedef unsigned long long	uint64;
typedef unsigned long 		uint32;
typedef unsigned short 		uint16;

static inline uint32 ts_diff(uint32 ts1, uint32 ts2)
	{
	return (ts1 < ts2) ? ts2 - ts1 : ts1 - ts2;
	}

// A sequence of timestamps from the same host
class TCPTSSeq
{
public:
	TCPTSSeq(string arg_name)
		: name(arg_name)
		{
		in_network_byte_order = -1; // unknown
		big_endian = little_endian = 0;
		latest = 0;
		latest_net_ts = 0;
		last_ts_seq = 0;
		sort_attempted = false;
		sort_successful = false;
		}

	void add(uint32 ts, double net_ts)
		{
		if ( ts == 0 )	// 0 means no timestamp
			return;

		ts = ntohl(ts);
		if ( ts_set.find(ts) != ts_set.end() )
			return;

		// DebugMsg("%.6f added tcp ts for %s: %08x", 
		// 	network_time, name.c_str(), ts);

		++num_tcp_timestamps;
		if ( num_tcp_timestamps % 100000 == 0 )
			DebugMsg("Number of TCP timestamps = %d", 
				num_tcp_timestamps);

		if ( ! ts_set.empty() )
			guess_byteorder(latest, ts);

		ts_set.insert(ts);
		latest = ts;
		latest_net_ts = net_ts;
		}

	void guess_byteorder(uint32 ts1, uint32 ts2)
		{
		// inspect byte order
		uint32 diff_ts = ts1 ^ ts2;
		uint32 differ_on_first_two_bytes = 
			diff_ts & 0xffff0000UL;
		uint32 differ_on_last_two_bytes = 
			diff_ts & 0x0000ffffUL;

		if ( differ_on_first_two_bytes && 
		     ! differ_on_last_two_bytes )
			++little_endian;

		else if ( ! differ_on_first_two_bytes && 
		     differ_on_last_two_bytes )
			++big_endian;

		else
			{
			uint32 diff_be = ts_diff(ts1, ts2);
			uint32 diff_le = ts_diff(
					reverse_byte_order(ts1), 
					reverse_byte_order(ts2));

			const uint32 max_diff = 0x1000000UL;
			if ( diff_be < diff_le && diff_be < max_diff )
				++big_endian;
			else if ( diff_le < diff_be && diff_le < max_diff)
				++little_endian;
			}
		}

	uint32 map(uint32 orig_ts)
		{
		if ( orig_ts == 0 ) // 0 == n/a
			return 0;

		if ( ! sort() )
			{
			if ( orig_ts == latest )
				return last_ts_seq;
			latest = orig_ts;
			++last_ts_seq;
			return htonl(last_ts_seq);
			}

		orig_ts = ntohl(orig_ts);
		if ( ! in_network_byte_order )
			orig_ts = reverse_byte_order(orig_ts);

		pair<ts_seq_it, ts_seq_it> pos = 
			equal_range(ts_seq.begin(), ts_seq.end(), orig_ts);

		if ( pos.first == pos.second ) 
			// not found
			internal_error("TCP timestamp 0x%08x not found for %s",
				orig_ts, name.c_str());
		
		uint32 ts = distance(ts_seq.begin(), pos.first) + 1;

		if ( ! in_network_byte_order )
			ts = reverse_byte_order(ts);
			
		return htonl(ts);
		}

	bool sort()
		{
		if ( sort_attempted )
			return sort_successful;

		sort_attempted = true;
		sort_successful = true;

		if ( ts_set.empty() )
			{
			sort_successful = false;
			return sort_successful;
			}

		if ( big_endian > little_endian )
			in_network_byte_order = 1;
		else if ( big_endian < little_endian )
			in_network_byte_order = 0;
		else
			{
			if ( ts_set.size() > 1 )
				{
				Alert("TCP timestamp byte order confused: %s: "
					"num_timestamps = %d, "
					"big_endian = %d, "
					"little_endian = %d",
					name.c_str(), ts_set.size(), 
					big_endian, little_endian);
				Export(PER_TRACE, 
					"cannot determine TCP timestamp byte order",
					name.c_str());
				}
			// Assume it's big endian
			in_network_byte_order = 1;
			}

		Note("TCP timestamp byte order info: %s: "
			"big_endian = %d, little_endian = %d",
			name.c_str(), big_endian, little_endian);

		if ( big_endian != 0 && little_endian != 0 ||
		     big_endian == 0 && little_endian == 0 )
			for ( ts_set_t::const_iterator it = ts_set.begin(); 
					it != ts_set.end(); ++it )
				DebugMsg("TCP timestamp of %s: 0x%08x", 
					name.c_str(), *it);

		for ( ts_set_t::const_iterator it = ts_set.begin(); 
				it != ts_set.end(); ++it )
			{
			uint32 ts = in_network_byte_order ? *it : 
				reverse_byte_order(*it);
			// DebugMsg("TCP timestamp of %s: 0x%08x", 
			// 	name.c_str(), ts);
			ts_seq.push_back(ts);
			}

		ts_set.clear();

		std::sort(ts_seq.begin(), ts_seq.end());

		return sort_successful;
		}

protected:
	string name;

	int in_network_byte_order;
	int big_endian, little_endian;

	// The latest TCP timestamp (not including those in the echo field)
	uint32 latest;
	double latest_net_ts; 	// The corresponding packet timestamp

	// All timestamps in the sequence
	typedef set<uint32> ts_set_t;
	ts_set_t ts_set;

	// And sorted ones (after byte order adjusted)
	typedef vector<uint32> ts_seq_t;
	typedef ts_seq_t::iterator ts_seq_it;
	ts_seq_t ts_seq;

	bool sort_attempted;
	bool sort_successful;

	// in case sort is unsuccessful, 
	uint32 last_ts_seq;
};

typedef map<uint32, TCPTSSeq *> tcp_ts_seq_map_t;
tcp_ts_seq_map_t tcp_ts_seq_map;

static TCPTSSeq * look_up_tcp_ts_seq(uint32 host)
	{
	tcp_ts_seq_map_t::const_iterator it = tcp_ts_seq_map.find(host);
	if ( it == tcp_ts_seq_map.end() )
		{
		TCPTSSeq *s = new TCPTSSeq(addr_to_string(host));
		tcp_ts_seq_map[host] = s;
		return s;
		}
	else
		return it->second;
	}

static void add_timestamp(uint32 host, uint32 tcp_ts, double net_ts)
	{
	look_up_tcp_ts_seq(host)->add(tcp_ts, net_ts);
	}

static uint32 map_timestamp(uint32 host, uint32 tcp_ts)
	{
	return look_up_tcp_ts_seq(host)->map(tcp_ts);
	}

DATA_PROCESSOR(renumber_tcp_timestamp)
	{
	ASSERT(len <= 10);

	const struct ip *ih = pkt_in->IPHeader();
	if ( ! ih )
		internal_error("Invalid IP header for renumbering TCP timestamps");

	uint32 src_addr = ntohl(ih->ip_src.s_addr);
	uint32 dst_addr = ntohl(ih->ip_dst.s_addr);
	double net_ts = pkt_in->Timestamp();
	uint32 ts = 0, echo_ts = 0;

	if ( len >= 6 ) // has the forward timestamp
		ts = *((uint32 *) (start + offset_in + 2));
	if ( len >= 10 ) // has the echo tiemstamp
		echo_ts = *((uint32 *) (start + offset_in + 6));

	if ( in_preprocessing )
		{
		add_timestamp(src_addr, ts, net_ts);
		add_timestamp(dst_addr, echo_ts, net_ts);
		ZERO_IT;
		return;
		}

	ts = map_timestamp(src_addr, ts);
	echo_ts = map_timestamp(dst_addr, echo_ts);

	u_char out_ts[10];
	bzero(out_ts, 10);

	out_ts[0] = TCPOPT_TIMESTAMP;
	out_ts[1] = len;
	memcpy(out_ts + 2, (const u_char *) &ts, 4);
	memcpy(out_ts + 6, (const u_char *) &echo_ts, 4);

	pkt_out->dump(out_ts, len, offset_out);
	offset_in += len;
	offset_out += len;
	}

}  // namespace tcpmkpub
