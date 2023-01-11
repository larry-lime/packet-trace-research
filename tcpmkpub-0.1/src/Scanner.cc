#include <sys/types.h>
#include <net/ethernet.h>

#include <deque>
#include <cstring>
#include <map>
#include <set>
#include <string>
using namespace std;

#include "common.h"
#include "Packet.h"
#include "Scanner.h"

namespace tcpmkpub {

const unsigned int kScanWindowSize = 20;
const unsigned int kScanThreshold = 16;

class Scanner 
{
public:
	enum Type { ARP, IP, OTHER };

	Scanner(in_addr_t addr, Type type)
		: addr_(addr), type_(type) {}
	Scanner(Scanner const &s)
		: addr_(s.addr()), type_(s.type()) {}

	in_addr_t addr() const	{ return addr_; }
	Type type() const	{ return type_; }

	inline bool operator<(Scanner const &s) const;
	string to_string() const 
		{
		const char *type_str;
		switch ( type() )
			{
			case ARP: 	type_str = "ARP"; break;
			case IP: 	type_str = "IP"; break;
			default: 	type_str = "OTHER"; break;
			}
		return addr_to_string(addr())
		       + " (" + type_str + ")";
		}

protected:
	in_addr_t addr_;
	Type type_;
};

// A sequence of addresses.  
class AddressSequence 
{
public:
	AddressSequence()
		: looks_like_sequential_scan(false) {}

	void Add(in_addr_t addr);
	bool LooksLikeSequentialScan() const 
		{ return looks_like_sequential_scan; }

protected:
  bool DetectSequentialScan(bool ascending);

	deque<in_addr_t> seq;
	set<in_addr_t> addr_in_seq;
	bool looks_like_sequential_scan;
};

// The set of scanners. 
// There are two ways to add a scanner: 
// (1) one can add a scanner statically through AddScanner(); or 
// (2) one can provide all potential <scanner, scannee> pairs, 
//     e.g., <IP-src, IP-dst> pairs, with AddPossibleScan(), and ScannerSet 
//     will detect scanners with a heuristic.
//
class ScannerSet {
public:
	void AddPossibleScan(Scanner const &scanner, in_addr_t const &scannee);
	void AddScanner(Scanner const &scanner);

	bool IsScanner(Scanner const &scanner);

protected:
	typedef map<Scanner, AddressSequence *> AddrSeqMap;
	AddrSeqMap addr_seq_map;
	set<Scanner> known_scanners;
};

bool Scanner::operator<(Scanner const &s) const
	{
	if ( type() != s.type() )
		return type() < s.type();
	else
		return addr() < s.addr();
	}

bool AddressSequence::DetectSequentialScan(bool ascending)
	{
	// length of longest monotonic subsequence
	vector<int> length_of_lms_ending_at;
	const int n = seq.size();
	for ( int i = 0; i < n; ++i )
		{
		int max_len = 1;  // seq[i] by itself
		for ( int j = 0; j < i; ++j )
			{
			// If seq[i] can be added to the sequence ending at j
			if ( ( ( ascending && seq[j] < seq[i] ) ||
			       ( ! ascending && seq[j] > seq[i] ) ) && 
			     length_of_lms_ending_at[j] >= max_len )
				{
				max_len = length_of_lms_ending_at[j] + 1;
				}
			}
		ASSERT((int) length_of_lms_ending_at.size() == i);
		length_of_lms_ending_at.push_back(max_len);
		}

	int max_len = 1;

	// Note that length_of_lms_ending_at[i] <= i + 1
	for ( int i = n - 1; i + 1 > max_len; --i )
		{
		if ( length_of_lms_ending_at[i] > max_len )
			max_len = length_of_lms_ending_at[i];
		}

	return max_len >= (int) kScanThreshold;
	}

void AddressSequence::Add(in_addr_t addr)
	{
	// Ignore repeated addresses in the window
	if ( addr_in_seq.find(addr) != addr_in_seq.end() )
		return;

	addr_in_seq.insert(addr);
	seq.push_back(addr);

	if ( seq.size() > kScanWindowSize )
		{
		in_addr_t first = seq.front();
		seq.pop_front();
		addr_in_seq.erase(first);
		}

	if ( seq.size() >= kScanWindowSize && 
	     ( DetectSequentialScan(true) || DetectSequentialScan(false) ) )
		{
		looks_like_sequential_scan = true;

		// Note the evidence
		string addresses;
		for ( unsigned int i = 0; i < seq.size(); ++i )
			{
			if ( i > 0 )
				addresses += " ";
			addresses += addr_to_string(seq[i]);
			}
		
		Note("found scanning: {%s}", addresses.c_str());
		}
	}

void ScannerSet::AddPossibleScan(Scanner const &scanner, 
                                 in_addr_t const &scannee)
	{
	// Skip known_scanners
	if ( known_scanners.find(scanner) != known_scanners.end() )
		return;

	ASSERT(note_off);
	note_off = false;

	AddressSequence *addr_seq;
	AddrSeqMap::iterator it = addr_seq_map.find(scanner);
	if ( it == addr_seq_map.end() )
		addr_seq_map[scanner] = addr_seq = new AddressSequence();
	else
		addr_seq = it->second;

	addr_seq->Add(scannee);

	// Add to known_scanners if the current address sequence looks like
	// scan.
	if ( addr_seq->LooksLikeSequentialScan() )
		{
		known_scanners.insert(scanner);
		Note("found scanner: %s", 
		     scanner.to_string().c_str());
		}

	note_off = true;
	}

void ScannerSet::AddScanner(Scanner const &scanner)
	{
	known_scanners.insert(scanner);
	}

bool ScannerSet::IsScanner(Scanner const &scanner)
	{
	// DebugMsg("check scanner %s", addr_to_string(scanner.addr()).c_str());
	return known_scanners.find(scanner) != known_scanners.end();
	}

ScannerSet *scanner_set()
	{
	static ScannerSet *the_set = 0;

	if ( ! the_set )
		{
		the_set = new ScannerSet();

#		define SCANNER(addr_str)				 \
			{ 						 \
			in_addr_t addr = to_addr(addr_str);		 \
			scanner_set()->AddScanner(			 \
				Scanner(addr, Scanner::IP)); 	 	 \
			}
#		include "local-policy/scanner.anon"
#		undef SCANNER

		}

	return the_set;
	}

// If the address at field "data_name" represent the host being scanned, who is 
// the scanner? 
Scanner get_scanner(InputPacket *pkt_in, const char *data_name)
	{
	try 
		{
		in_addr_t peer;
		Scanner::Type scanner_type;

		if ( pkt_in->EtherType() == ETHERTYPE_IP )
			{
			scanner_type = Scanner::IP;
			if ( strcmp(data_name, "IP_srcaddr") == 0 ||
			     strcmp(data_name, "ICMP_redirect_gateway") == 0 )
				{
				peer = pkt_in->GetRegisteredIPAddr("IP_dstaddr", false);
				}
			else if ( strcmp(data_name, "IP_dstaddr") == 0 ||
			          // router redirect
			          strcmp(data_name, "IPOPT_rr") == 0 )
				{
				peer = pkt_in->GetRegisteredIPAddr("IP_srcaddr", false);
				}
			else if ( strcmp(data_name, "ETHER_srcaddr") == 0 )
				{
				peer = pkt_in->GetRegisteredIPAddr("IP_dstaddr", true);
				}
			else if ( strcmp(data_name, "ETHER_dstaddr") == 0 )
				{
				peer = pkt_in->GetRegisteredIPAddr("IP_srcaddr", true);
				}
			else
				{
				throw Exception("%.6f unknown field '%s' "
				                "for get_scanner (IP)",
				                network_time, data_name);
				}
			}

		else if ( pkt_in->EtherType() == ETHERTYPE_ARP )
			{
			scanner_type = Scanner::ARP;
			if ( strcmp(data_name, "ARP_spa") == 0 || 
			     strcmp(data_name, "ARP_sha") == 0 )
				{
				peer = pkt_in->GetRegisteredIPAddr("ARP_tpa", false);
				}
			else if ( strcmp(data_name, "ARP_tpa") == 0 ||
			          strcmp(data_name, "ARP_tha") == 0 )
				{
				peer = pkt_in->GetRegisteredIPAddr("ARP_spa", false);
				}
			else if ( strcmp(data_name, "ETHER_srcaddr") == 0 )
				{
				peer = pkt_in->GetRegisteredIPAddr("ARP_tpa", true);
				}
			else if ( strcmp(data_name, "ETHER_dstaddr") == 0 )
				{
				peer = pkt_in->GetRegisteredIPAddr("ARP_spa", true);
				}
			else
				{
				throw Exception("%.6f unknown field '%s' "
				                "for get_scanner (ARP)",
				                network_time, data_name);
				}
			}

		else
			{
			if ( strcmp(data_name, "ETHER_srcaddr") == 0 ||
			     strcmp(data_name, "ETHER_dstaddr") == 0 )
				{
				return Scanner(0, Scanner::OTHER);
				}
			else
				{
				throw Exception("%.6f unknown field '%s' "
			                	"for get_scanner (other)",
				        	network_time, data_name);
				}
			}

		return Scanner(peer, scanner_type);
		}
	catch ( Exception &e )
		{
		Alert("cannot get scanner for '%s'", data_name);
		return Scanner(0, Scanner::OTHER);
		}
	}

string scanner_to_string(ScannerID scanner)
	{
	switch ( scanner )
		{
		case NO_SCANNER: 	return "regular";
		case ARP_SCANNER:	return "arp-scanner";
		case IP_SCANNER:	return "ip-scanner";
		default:
			internal_error("unknown scanner type %d", scanner);
			return "unknown-scanner";
		}
	}

void detect_scanner(in_addr_t addr, InputPacket *pkt_in, const char *data_name)
	{
	scanner_set()->AddPossibleScan(get_scanner(pkt_in, data_name), addr);
	}

ScannerID check_scanner(InputPacket *pkt_in, const char *data_name)
	{
	Scanner scanner(get_scanner(pkt_in, data_name));
	
	if ( scanner_set()->IsScanner(scanner) )
		{
		switch ( scanner.type() ) 
			{
			case Scanner::ARP:
				return ARP_SCANNER;
			case Scanner::IP:
				return IP_SCANNER;
			default:
				internal_error("unknown scanner type %d", 
				               scanner.type());
			}
		}

	return NO_SCANNER;
	}

}  // namespace tcpmkpub
