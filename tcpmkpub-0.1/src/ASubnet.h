#ifndef ASubnet_h
#define ASubnet_h

#include <string>
#include <map>
#include <set>
#include <list>
using namespace std;

#include "Hash.h"
#include "Prefix.h"
#include "PrefixTree.h"
#include "RPerm.h"
#include "IPAddr.h"

namespace tcpmkpub {

class EnterpriseSubnet;
class AEnt;

class ASubnet : public IPAnonymizer
{
public:
	ASubnet(HashKey key, AEnt *aent, const EnterpriseSubnet *subnet, int flags);

	static const int PRESERVE_GATEWAY = 1;
	static const int PRESERVE_BROADCAST = 2;

	in_addr_t Anonymize(IPAddr const & addr);
	void GenerateNotes();

protected:
	HashKey key;
	AEnt *aent;
	const EnterpriseSubnet *subnet;
	int flags;
	Prefix prefix;
	set<in_addr_t> suffix_to_preserve;
};

class ASubnetGroup : public IPAnonymizer
{
public:
	ASubnetGroup(HashKey key, string name, const vector<Prefix> &net_prefixes);
	void add_subnet(const Prefix &prefix);
	void finalize();
	
	in_addr_t Anonymize(IPAddr const & addr);
	void GenerateNotes();

protected:
	void settle(int prefix_len, vector<Prefix>& available_prefixes);
	in_addr_t pick_available_addr(in_addr_t addr);

	HashKey key;
	string name;
	vector<Prefix> nets;
	vector<Prefix> subnets;

	bool finalized;
	PrefixTree<Prefix> subnet_tree;

	// for addresses not in any subnet
	list<in_addr_t> available_addresses;
	map<in_addr_t, in_addr_t> other_addresses;
};

}  // namespace tcpmkpub

#endif /* ASubnet_h */
