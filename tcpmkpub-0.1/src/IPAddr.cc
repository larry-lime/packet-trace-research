#include <set>
using namespace std;

#include "Anon.h"
#include "AEnt.h"
#include "Scanner.h"

namespace tcpmkpub {

class IPAnonymizerWithMap : public IPAnonymizer
{
public:
	IPAnonymizerWithMap(IPAnonymizer *A)
		{
		base = A;
		}

	void Preprocess(in_addr_t addr)
		{
		base->Preprocess(addr);
		}

	in_addr_t Anonymize(IPAddr const &addr)
		{
		map<IPAddr, in_addr_t>::const_iterator it = 
			ip_anon_map.find(addr);
		if ( it != ip_anon_map.end() )
			return it->second;
		in_addr_t a = base->Anonymize(addr);
		ip_anon_map[addr] = a;

		Note("IP address mapping (%s %.6f) %s (%s) -> %s", 
			input_filename ? input_filename : "<none>", 
			network_time,
			addr_to_string(addr.addr()).c_str(),
			scanner_to_string(addr.scanner()).c_str(),
			addr_to_string(a).c_str());
		return a;
		}

	void GenerateNotes()
		{
		base->GenerateNotes();
		}

protected:
	IPAnonymizer *base;
	map<IPAddr, in_addr_t> ip_anon_map;
};

static IPAnonymizer *ip_anonymizer = 0;

void init_ip_addr_anonymization(HashKey key, Topology *topology)
	{
	if ( ip_anonymizer )
		return;
	ip_anonymizer = new IPAnonymizerWithMap(
		new AEnt(AEnt::PRESERVE_CLASS | 
		         AEnt::PRESERVE_CLASSD_ADDR | 
		         AEnt::PRESERVE_PRIV_ADDR,
		         key, 
		         topology));
	}

void finish_ip_addr_anonymization()
	{
	ASSERT(ip_anonymizer);
	ip_anonymizer->GenerateNotes();
	delete ip_anonymizer;
	}

void preprocess_ip_addr(in_addr_t addr)
	{
	if ( ! ip_anonymizer )
		throw Exception("IP anonymizer not initialized");
	ip_anonymizer->Preprocess(addr);
	}

in_addr_t anonymize_ip_addr(IPAddr const & input)
	{
	if ( ! ip_anonymizer )
		throw Exception("IP anonymizer not initialized");
	return ip_anonymizer->Anonymize(input);
	}

DATA_PROCESSOR(anonymize_ip_addr)
	{
	if ( len < 4 || offset_in + 4 > caplen )
		{
		if ( ! pkt_in->truncated() )
			Alert("incomplete IP address");
		if ( offset_in + len > caplen )
			len = caplen - offset_in;
		ZERO_IT;
		return;
		}

	in_addr_t addr = 
		ntohl(*reinterpret_cast<const in_addr_t*>
			(start + offset_in));
	offset_in += 4;

	if ( in_preprocessing )
		{
		preprocess_ip_addr(addr);
		detect_scanner(addr, pkt_in, data_name);
		}
	else
		{
		IPAddr ip_addr(addr, check_scanner(pkt_in, data_name));
		// Set the scan bit on the input packet
		if ( ip_addr.scanner() != NO_SCANNER )
			pkt_in->set_scan();
		addr = ip_anonymizer->Anonymize(ip_addr);
		addr = htonl(addr);
		pkt_out->dump((const u_char *) &addr, 4, offset_out);
		offset_out += 4;
		}
	}

DATA_PROCESSOR(register_ip_addr)
	{
	if ( len < 4 || offset_in + 4 > caplen )
		{
		if ( ! pkt_in->truncated() )
			Alert("incomplete IP address");

		if ( offset_in + len > caplen )
			len = caplen - offset_in;
		ZERO_IT;
		return;
		}

	u_long addr = ntohl(*((u_long*) (start + offset_in)));
	// DebugMsg("to register %s as '%s'", 
	//          addr_to_string(addr).c_str(), data_name);
	pkt_in->RegisterIPAddr(data_name, addr);
	ZERO_IT;
	}

}  // namespace tcpmkpub
