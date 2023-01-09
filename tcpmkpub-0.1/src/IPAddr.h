#ifndef ipaddr_h
#define ipaddr_h

#include "Hash.h"
#include "Scanner.h"

namespace tcpmkpub {

class Topology;

class IPAddr
{
public:
	explicit IPAddr(in_addr_t addr, ScannerID scanner)
		: addr_(addr), scanner_(scanner) {}

	in_addr_t addr() const 		{ return addr_; }

	// The scanner ID if the address is *being* scanned. Addresses
	// of different scanner ID are mapped differently. 
	ScannerID scanner() const 	{ return scanner_; }

	bool operator<(IPAddr const &x) const
		{
		if ( addr() != x.addr() )
			return addr() < x.addr();
		else
			return scanner() < x.scanner();
		}

protected:
	in_addr_t addr_;
	ScannerID scanner_;
};

// The IPAnonymizer interface
class IPAnonymizer
{
public:
	virtual ~IPAnonymizer() {}

	virtual in_addr_t Anonymize(IPAddr const &) = 0;
	virtual void Preprocess(in_addr_t addr)
		{
		// do nothing by default
		}
	virtual void GenerateNotes() = 0;
};

void init_ip_addr_anonymization(HashKey key, Topology *topology);
void finish_ip_addr_anonymization();

}  // namespace tcpmkpub

#endif /* ipaddr_h */
