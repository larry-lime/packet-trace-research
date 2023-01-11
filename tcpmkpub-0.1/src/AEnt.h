#ifndef AEnt_h
#define AEnt_h

#include "Hash.h"
#include "IPAddr.h"
#include "PrefixTree.h"
#include "Topology.h"

namespace tcpmkpub {

class A49;
class ASubnetGroup;
class ASubnet;

class AEnt : public IPAnonymizer
{
public:
	AEnt(int flags, HashKey key, Topology *topology);

	// Flags for AEnt() is OR of zero or more following values
	enum AEntFLags {
		PRESERVE_CLASS 		= 1,
		PRESERVE_CLASSD_ADDR 	= 2,
		PRESERVE_PRIV_ADDR	= 4,
	};

	~AEnt();

	// Add address for preprocessing.
	void AddAddress(in_addr_t addr);

	// Anonymize the address and returns the resulting address in host 
	// byte-order.
	in_addr_t Anonymize(IPAddr const &addr);

	void Preprocess(in_addr_t addr);

	// Generate notes about the anonymization mapping
	void GenerateNotes();

protected:
	int flags;
	Topology *topology;

	// Used to keep "pseudo" subnets created for class D and private 
	// addresses
	vector<EnterpriseSubnet *> auxiliary_subnets;

	// Anonymizers

	// For external addresses and network prefixes of internal ones
	A49 *a49;

	// For internal parts of addresses. Generally speaking, level-1 
	// anonymizers are used to remap subnet prefixes, while level-2 
	// ones remap intra-subnet addresses.
	PrefixTree<IPAnonymizer*> ianon_level1[2];
	PrefixTree<IPAnonymizer*> ianon_level2[2];
};

}  // namespace tcpmkpub

#endif /* AEnt_h */
