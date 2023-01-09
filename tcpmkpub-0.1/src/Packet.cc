#include "common.h"
#include "Packet.h"

#include <pcap.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

namespace tcpmkpub {

Packet::Packet()
	{
	pkt_data = 0;
	pkt_data_len = 0;
	ll_hdr_offset = net_hdr_offset = transport_hdr_offset = -1;
	net_hdr_offset_stack.push_back(-1);
	transport_hdr_offset_stack.push_back(-1);
	}

void Packet::SetEtherHeader(int offset)
	{
	if ( offset >= 0 && offset <= pkt_data_len )
		ll_hdr_offset = offset;
	}

void Packet::SetNetHeaderOffset(int offset)
	{
	if ( net_hdr_offset >= 0 ) // already set
		internal_error("cannot SetIPHeader again once it's set");

	// Do not push to the stack as the offset is tentative
	net_hdr_offset = offset;
	}

void Packet::PushNetHeader(int offset)
	{
	if ( offset >= 0 && offset <= pkt_data_len )
		{
		net_hdr_offset = offset;
		net_hdr_offset_stack.push_back(offset);
		}
	}

void Packet::PopNetHeader()
	{
	net_hdr_offset_stack.pop_back();
	
	// do not set the top most one to -1
	if ( net_hdr_offset_stack.size() > 1 ) 
		net_hdr_offset = net_hdr_offset_stack.back();
	}

void Packet::PushTransportHeader(int offset)
	{
	if ( offset >= 0 && offset <= pkt_data_len )
		{
		transport_hdr_offset = offset;
		transport_hdr_offset_stack.push_back(offset);
		}
	}

void Packet::PopTransportHeader()
	{
	transport_hdr_offset_stack.pop_back();
	transport_hdr_offset = transport_hdr_offset_stack.back();
	}

int Packet::NetworkHeaderOffset(bool top_level) const
	{
	if ( top_level )
		{
		return ( net_hdr_offset_stack.size() >= 2 ) ?
		       net_hdr_offset_stack[1] : -1;
		}
	else
		{
		return net_hdr_offset;
		}
	}

const struct ether_header *Packet::EthernetHeader() const
	{
	if ( ll_hdr_offset >= 0 && 
	     ll_hdr_offset + (int) sizeof(struct ether_header) <= pkt_data_len )
		{
		return reinterpret_cast<const struct ether_header *>
			(pkt_data + ll_hdr_offset);
		}
	else
		{
		return 0;
		}
	}

const struct arphdr *Packet::ARPHeader() const
	{
	if ( EtherType() != ETHERTYPE_ARP )
		return 0;

	int offset = NetworkHeaderOffset(false);
	if ( offset >= 0 && offset + (int) sizeof(struct arphdr) <= pkt_data_len )
		{
		return reinterpret_cast<const struct arphdr *>
			(pkt_data + offset);
		}
	else
		return 0;
	}

const struct ip *Packet::IPHeader(bool top_level) const
	{
	if ( EtherType() != ETHERTYPE_IP )
		return 0;

	int offset = NetworkHeaderOffset(top_level);
	if ( offset >= 0 && offset + (int) sizeof(struct ip)<= pkt_data_len )
		{
		return reinterpret_cast<const struct ip *>
			(pkt_data + offset);
		}
	else
		return 0;
	}

const struct tcphdr *Packet::TCPHeader() const
	{
	if ( transport_hdr_offset >= 0 && 
	     IPProto() == IPPROTO_TCP && 
	     transport_hdr_offset + (int) sizeof(struct tcphdr)<= pkt_data_len )
		{
		return reinterpret_cast<const struct tcphdr *>
			(pkt_data + transport_hdr_offset);
		}
	else
		return 0;
	}

const struct udphdr *Packet::UDPHeader() const
	{
	if ( transport_hdr_offset >= 0 && 
	     IPProto() == IPPROTO_UDP && 
	     transport_hdr_offset + (int) sizeof(struct udphdr)<= pkt_data_len )
		{
		return reinterpret_cast<const struct udphdr *>
			(pkt_data + transport_hdr_offset);
		}
	else
		return 0;
	}

const struct icmp *Packet::ICMPHeader() const
	{
	if ( transport_hdr_offset >= 0 && 
	     IPProto() == IPPROTO_ICMP && 
	     transport_hdr_offset + 4 <= pkt_data_len )
		{
		return reinterpret_cast<const struct icmp *>
			(pkt_data + transport_hdr_offset);
		}
	else
		return 0;
	}

int Packet::EtherType() const 
	{
	const struct ether_header *eth_hdr = EthernetHeader();
	return eth_hdr ? ntohs(eth_hdr->ether_type) : -1;
	}

int Packet::IPProto() const
	{
	const struct ip *ip_hdr = IPHeader();
	return ip_hdr ? ip_hdr->ip_p : -1;
	}

u_long Packet::IPChkSum() const
	{
	const struct ip *ip_hdr = IPHeader();
	return ip_hdr ? (int) (ip_hdr->ip_sum) : -1;
	}

int Packet::IPFragOffset() const
	{
	const struct ip *ip_hdr = IPHeader();
	return ip_hdr ? (int) (ntohs(ip_hdr->ip_off) & 0x1fff) : -1;
	}

bool Packet::is_fragmented() const
	{
	const struct ip *ip_hdr = IPHeader();
	return (ip_hdr && (ntohs(ip_hdr->ip_off) & 0x3fff)); 
	}

int Packet::IPHdrLen() const
	{
	const struct ip *ip_hdr = IPHeader();
	return ip_hdr ? (int) (ip_hdr->ip_hl * 4) : -1;
	}

int Packet::IPOptionLen() const
	{
	const struct ip *ip_hdr = IPHeader();
	return ip_hdr ? (int) (IPHdrLen() - sizeof(*ip_hdr)) : -1;
	}

int Packet::IPLen() const
	{
	const struct ip *ip_hdr = IPHeader();
	return ip_hdr ? (int) (ntohs(ip_hdr->ip_len)) : -1;
	}

int Packet::IPPayloadLen() const
	{
	const struct ip *ip_hdr = IPHeader();
	return ip_hdr ? (int) (IPLen() - IPHdrLen()) : -1;
	}

int Packet::TCPHdrLen() const
	{
	const struct tcphdr *tcp_hdr = TCPHeader();
	return tcp_hdr ? (int) (tcp_hdr->th_off * 4) : -1;
	}

int Packet::TCPOptionLen() const
	{
	const struct tcphdr *tcp_hdr = TCPHeader();
	return tcp_hdr ? (int) (TCPHdrLen() - sizeof(*tcp_hdr)) : -1;
	}

int Packet::TCPChkSum() const
	{
	const struct tcphdr *tcp_hdr = TCPHeader();
	return tcp_hdr ? (int) (tcp_hdr->th_sum) : -1;
	}

int Packet::UDPChkSum() const
	{
	const struct udphdr *udp_hdr = UDPHeader();
	return udp_hdr ? (int) (udp_hdr->uh_sum) : -1;
	}

int Packet::ICMPType() const
	{
	const struct icmp *icmp_hdr = ICMPHeader();
	return icmp_hdr ? (int) (icmp_hdr->icmp_type) : -1;
	}

int Packet::ICMPChkSum() const
	{
	const struct icmp *icmp_hdr = ICMPHeader();
	return icmp_hdr ? (int) (icmp_hdr->icmp_cksum) : -1;
	}

int Packet::TransportLen() const
	{
	if ( transport_hdr_offset < 0 )
		return -1;
	int transport_len = IPPayloadLen();
	if ( transport_hdr_offset + transport_len > Len() )
		transport_len = Len() - transport_hdr_offset;
	return transport_len;
	}

string Packet::FlowID() const
	{
	const struct ip *iphdr = IPHeader(true);
	if ( ! iphdr )
		return "(truncated IP header)";

	return string(is_embedded_pkt() ? "(embedded) " : "")
		+ addr_to_string(ntohl(iphdr->ip_src.s_addr)) 
		+ " > " 
		+ addr_to_string(ntohl(iphdr->ip_dst.s_addr));
	}

namespace  // private namespace
	{
	string FieldID(int level, const char *data_name)
		{
		char buf[16];
		snprintf(buf, sizeof(buf), "(%d)", level);
		return string(data_name) + buf;
		}
	}

void InputPacket::RegisterIPAddr(const char *data_name, in_addr_t addr)
	{
	int level = net_hdr_offset_stack.size() - 1;
	string field_id = FieldID(level, data_name);
	if ( ip_addresses.find(field_id) != ip_addresses.end() )
		{
		throw Exception("%.6f field '%s' already registered",
			network_time, field_id.c_str());
		}
	// DebugMsg("register %s as '%s'", 
	//          addr_to_string(addr).c_str(), field_id.c_str());
	ip_addresses[field_id] = addr;
	}

in_addr_t InputPacket::GetRegisteredIPAddr(const char *data_name, 
                                           bool top_level) const
	{
	int level = top_level ? 1 : net_hdr_offset_stack.size() - 1;
	string field_id = FieldID(level, data_name);
	map<string, in_addr_t>::const_iterator it = 
		ip_addresses.find(field_id);
	if ( it == ip_addresses.end() )
		{
		throw Exception("%.6f field '%s' not registered",
			network_time, field_id.c_str());
		}
	return it->second;
	}

InputPacket::InputPacket(const pcap_pkthdr &hdr, const u_char* pkt)
	: Packet()
	{
	pkt_data = pkt;
	pkt_data_len = hdr.caplen;

	pcap_hdr = hdr;
	ts = pcap_hdr.ts.tv_sec + 0.000001 * pcap_hdr.ts.tv_usec;
	is_scan_ = false;
	truncated_ = false;
	}

OutputPacket::OutputPacket(int init_buf_len)
	: Packet()
	{
	if ( init_buf_len < 68 )
		init_buf_len = 68;

	pkt_buf_len = init_buf_len;
	pkt_data = new u_char[pkt_buf_len];
	}

OutputPacket::~OutputPacket()
	{
	delete [] pkt_data;
	}

void OutputPacket::dump(const u_char* data, int len, int dest_offset)
	{
	if ( len <= 0 )
		return;

	prepare_buf(dest_offset, len);

	memcpy((void *) (pkt_data + dest_offset), data, len);

	if ( dest_offset + len > pkt_data_len )
		pkt_data_len = dest_offset + len;
	}

void OutputPacket::dump(u_char data, int len, int dest_offset)
	{
	if ( len <= 0 )
		return;

	prepare_buf(dest_offset, len);

	memset((void *) (pkt_data + dest_offset), data, len);

	if ( dest_offset + len > pkt_data_len )
		pkt_data_len = dest_offset + len;
	}

void OutputPacket::prepare_buf(int offset, int len)
	{
	if ( offset > pkt_data_len )
		throw Exception("dumping beyond the tail of output packet");

	if ( offset + len <= pkt_buf_len )
		return;

	pkt_buf_len += pkt_buf_len;
	if ( offset + len > pkt_buf_len )
		pkt_buf_len = offset + len;

	const u_char *old_buf = pkt_data;
	pkt_data = new u_char[pkt_buf_len];
	memcpy((void *) pkt_data, old_buf, pkt_data_len);
	delete [] old_buf;
	}

}  // namespace tcpmkpub
