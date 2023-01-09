#ifndef packet_h
#define packet_h

#include <sys/types.h>
#include <pcap.h>

#include <map>
#include <string>
#include <vector>
using namespace std;

#include "common.h"

struct ether_header;
struct arphdr;
struct ip;
struct tcphdr;
struct udphdr;
struct icmp;

namespace tcpmkpub {

class Packet
{
public:
	Packet();

	int Len() const			{ return pkt_data_len; }
	const u_char* Pkt() const	{ return pkt_data; }

	void SetEtherHeader(int offset);

	bool is_embedded_pkt() const { return net_hdr_offset_stack.size() > 2; }

	void PushNetHeader(int offset);
	void PopNetHeader();

	// Tentatively set the IP header offset, which is needed for scanner
	// detection when processing the ethernet header
	void SetNetHeaderOffset(int offset);

	void PushTransportHeader(int offset);
	void PopTransportHeader();

	int NetworkHeaderOffset(bool top_level) const;

	const struct ether_header *	EthernetHeader() const;
	const struct arphdr *		ARPHeader() const;
	const struct ip *		IPHeader(bool top_level = false) const;
	const struct tcphdr *		TCPHeader() const;
	const struct udphdr *		UDPHeader() const;
	const struct icmp *		ICMPHeader() const;

	int EtherType() const;

	int IPProto() const;
	u_long IPChkSum() const;
	int IPFragOffset() const;
	bool is_fragmented() const;
	int IPHdrLen() const;
	int IPOptionLen() const;
	int IPLen() const;
	int IPPayloadLen() const;

	int TCPHdrLen() const;
	int TCPOptionLen() const;
	int TCPChkSum() const;
	int UDPChkSum() const;
	int ICMPType() const;
	int ICMPChkSum() const;
	int TransportLen() const;

	string FlowID() const;

protected:
	const u_char *pkt_data;
	int pkt_data_len;
	int ll_hdr_offset, net_hdr_offset, transport_hdr_offset;
	vector<int> net_hdr_offset_stack, transport_hdr_offset_stack;
};

class InputPacket : public Packet
{
public:
	InputPacket(const pcap_pkthdr &hdr, const u_char* pkt);

	double Timestamp() const { return ts; }

	// Register the IP address contained in field "data_name". The 
	// addresses are useful for anonymizing other IP addresses in 
	// the packet. For example, when anonymizing the destination IP
	// address, we need to check if the source is a scanner host.
	//
	// Note that the field name is relative to network header stack. 
	// That is, we create two entries for the same data name, e.g.,
	//  "IP_dst", for the outermost IP header and for the one contained
	// in ICMP-unreach payload.
	//
	// The addresses are in host byte order in both following functions
	void RegisterIPAddr(const char *data_name, in_addr_t addr);

	// Get the IP address registered to the field "data_name".
	in_addr_t GetRegisteredIPAddr(const char *data_name, 
	                              bool top_level) const;

	bool is_scan() const	{ return is_scan_; }
	void set_scan()		{ is_scan_ = true; }

	int pcap_len() const	{ return pcap_hdr.len; }
	int pcap_caplen() const	{ return pcap_hdr.caplen; }

	bool truncated() const	{ return truncated_; }

	inline void CheckTruncation(const char *name, 
                                   int offset_in, 
                                   int data_len, 
                                   int caplen,
                                   bool alert)
		{
		// Ignore if the packet is already truncated
		if ( truncated_ )
			return;
		truncated_ = true;
		if ( alert )
			{
			Alert("truncated data for '%s' in %s: %d + %d > %d", 
				name, FlowID().c_str(),
				offset_in, data_len, caplen);
			}
		}

protected:
	pcap_pkthdr pcap_hdr;
	double ts;
	map<string, in_addr_t> ip_addresses;
	bool truncated_;
	bool is_scan_;
};

class OutputPacket : public Packet
{
public:
	OutputPacket(int init_buf_len);
	~OutputPacket();

	void reset() 	{ pkt_data_len = 0; }
	void dump(const u_char* data, int len, int dest_offset);
	void dump(u_char data, int len, int dest_offset);

protected:
	void prepare_buf(int offset, int len);

	int pkt_buf_len;
};

}  // namespace tcpmkpub

#endif /* packet_h */
