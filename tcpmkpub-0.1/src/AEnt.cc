#include "A49.h"
#include "AEnt.h"
#include "ASubnet.h"
#include "Anon.h"
#include "Topology.h"

#include <algorithm>
using namespace std;

namespace tcpmkpub {

AEnt::~AEnt()
	{
	// Clear up auxiliary subnets for class D and private networks
	vector<EnterpriseSubnet *>::const_iterator subnet_it;
	for ( subnet_it = auxiliary_subnets.begin();
	      subnet_it != auxiliary_subnets.end();
	      ++subnet_it )
		{
		delete *subnet_it;
		}
	}

AEnt::AEnt(int arg_flags,
           HashKey key, 
           Topology *arg_topology)
	{
	flags = arg_flags;
	topology = arg_topology;

	vector<EnterpriseNetwork *>::const_iterator net_it;
	vector<EnterpriseSubnet *>::const_iterator subnet_it;
	vector<Prefix>::const_iterator prefix_it;

	const int REGULAR = 0;
	const int IP_SCAN = 1;

	// Prefixes that are not prefix-preserving with neightboring prefixes
	vector<Prefix> a49_separatists;

	// Class D addresses
	// The host parts of class D addresses are not anonymized with the A50 
	// (prefix-preserving) algorithm. They are either preserved or randomly
	// renumbered.
	//
	Prefix class_d("224.0.0.0/3");
	ASubnet *class_d_address_anonymizer = 0;
	if ( ! (flags & PRESERVE_CLASSD_ADDR) )
		{
		EnterpriseSubnet *subnet = new EnterpriseSubnet(class_d);
		auxiliary_subnets.push_back(subnet);
		class_d_address_anonymizer = new ASubnet(key, this, subnet, 0);
		}
	ianon_level1[REGULAR].insert(class_d, class_d_address_anonymizer);

	vector<Prefix> privnet;
	privnet.push_back(Prefix("0.0.0.0/32"));
	privnet.push_back(Prefix("255.255.255.255/32"));
	privnet.push_back(Prefix("10.0.0.0/8"));
	privnet.push_back(Prefix("172.16.0.0/12"));
	privnet.push_back(Prefix("192.168.0.0/16"));
	privnet.push_back(Prefix("169.254.0.0/16"));
	for ( prefix_it = privnet.begin(); 
	      prefix_it != privnet.end(); 
	      ++prefix_it )
		{
		// We treat private addresses similarly as class D addresses --
		// preserve or randomly renumber.
		EnterpriseSubnet *subnet = new EnterpriseSubnet(*prefix_it);
		auxiliary_subnets.push_back(subnet);
		ianon_level1[REGULAR].insert(*prefix_it, 
		            (flags & PRESERVE_PRIV_ADDR) ?
		            0 : 
		            new ASubnet(key, this, subnet, 0));

		// Also, private prefixes are anonymized independently of 
		// neighboring prefixes.
		a49_separatists.push_back(*prefix_it);
		}

	// Go over the enterprise networks for three tasks:
	// 1. Create a ASubnetGroup (renumbering of subnets) for each network.
	// 2. Add each prefix and the corresponding ASubnetGroup to ianon_level1.
	// 3. Add each prefix to a49_separatists.
	
	const vector<EnterpriseNetwork *> &enterprise_networks = 
		topology->enterprise_networks();

	for ( net_it = enterprise_networks.begin();
	      net_it != enterprise_networks.end();
	      ++net_it )
		{
		const EnterpriseNetwork *net = *net_it;
		const vector<Prefix> net_prefixes = net->prefixes();

		ASubnetGroup *asubnetgroup = 
			new ASubnetGroup(key, net->name(), net_prefixes);
		ASubnetGroup *asubnetgroup_scan = 
			new ASubnetGroup(key, net->name(), net_prefixes);

		for ( prefix_it = net_prefixes.begin();
		      prefix_it != net_prefixes.end();
		      ++prefix_it )
			{
			const Prefix &p = *prefix_it;
			a49_separatists.push_back(p);

			ianon_level1[REGULAR].insert(p, asubnetgroup);

			ianon_level1[IP_SCAN].insert(p, asubnetgroup_scan);
			asubnetgroup_scan->add_subnet(p);

			EnterpriseSubnet *pseudo_scan_subnet = 
				new EnterpriseSubnet(p);
			auxiliary_subnets.push_back(pseudo_scan_subnet);
			ianon_level2[IP_SCAN].insert(p, 
				new ASubnet(key, this, pseudo_scan_subnet, 0));
			}

		// Go over the subnets, also for three tasks:
		// 1. Create a ASubnet (renumbering of host part) for each 
		//    subnet 
		// 2. Add each subnet prefix and the corresponding ASubnet to 
		//    ianon_level2.
		// 3. Add each subnet to its corresponding ASubnetGroup
		// 
		const vector<EnterpriseSubnet *> &subnets = net->subnets();

		if ( subnets.empty() )
			{
			throw Exception("network %s does not contain any subnet",
			                net->name().c_str());
			}

		for ( subnet_it = subnets.begin(); 
		      subnet_it != subnets.end(); 
		      ++subnet_it )
			{
			const EnterpriseSubnet *subnet = *subnet_it;
			const Prefix &subnet_prefix = subnet->prefix();

			if ( subnet->break_up() )
				{
				// Break up the subnet as if each address is 
				// on an individual subnet
				for ( in_addr_t x = subnet_prefix.addr(); 
				      subnet_prefix.includes(x); 
				      ++x )
					{
					asubnetgroup->add_subnet(Prefix(x, 32));
					}
				}
			else
				{
				ASubnet *asubnet = new ASubnet(key, this, subnet,  
					ASubnet::PRESERVE_GATEWAY | 
					ASubnet::PRESERVE_BROADCAST);

				// Add the subnet prefix to ianon_level2, so that the 
				// host part will be anonymized with the 
				// corresponding ASubnet.
				ianon_level2[REGULAR].insert(subnet_prefix, asubnet);

				// Add the subnet to the ASubnetGroup
				asubnetgroup->add_subnet(subnet_prefix);
				}
			}

		// Now we have added all the subnets to the group, let it
		// figure out how to renumber them.
		asubnetgroup->finalize();
		asubnetgroup_scan->finalize();
		}

	// Init the A49 prefix-preserving anonymizer
	vector<Prefix> to_preserve;
	if ( flags & PRESERVE_CLASS )
		to_preserve.push_back(Prefix("224.0.0.0/3"));
	a49 = new A49(key, to_preserve, a49_separatists);
	}
	

void AEnt::Preprocess(in_addr_t addr)
	{
	a49->Preprocess(addr);
	}

in_addr_t AEnt::Anonymize(IPAddr const & addr)
	{
	PrefixVal<IPAnonymizer*> pv;

	IPAddr x = addr;
	in_addr_t prefix_mask = first_n_bit_mask(32);

	int ianon_index = 
		( addr.scanner() == IP_SCANNER ) ? 1 : 0;

	if ( ianon_level2[ianon_index].look_up_prefix(x.addr(), &pv) )
		{
		if ( pv.val )
			x = IPAddr(pv.val->Anonymize(x), x.scanner());
		prefix_mask = pv.prefix.mask();
		}

	if ( ianon_level1[ianon_index].look_up_prefix(x.addr(), &pv) )
		{
		if ( pv.val )
			x = IPAddr(pv.val->Anonymize(x), x.scanner());
		prefix_mask = pv.prefix.mask();
		}

	in_addr_t a49_output = a49->Anonymize(x);

	return (a49_output & prefix_mask) | (x.addr() & ~prefix_mask);
	}

void AEnt::GenerateNotes()
	{
	vector<EnterpriseNetwork *>::const_iterator net_it;
	vector<EnterpriseSubnet *>::const_iterator subnet_it;
	vector<Prefix>::const_iterator prefix_it;
	
	const vector<EnterpriseNetwork *> &enterprise_networks = 
		topology->enterprise_networks();

	// Renumbered subnet prefixes
	vector<Prefix> renumbered_subnet_prefixes;
	PrefixTree<IPAnonymizer *> asubnet_by_prefix_anon;

	for ( net_it = enterprise_networks.begin();
	      net_it != enterprise_networks.end();
	      ++net_it )
		{
		const EnterpriseNetwork *net = *net_it;
		const vector<Prefix> net_prefixes = net->prefixes();

		for ( prefix_it = net_prefixes.begin();
		      prefix_it != net_prefixes.end();
		      ++prefix_it )
			{
			const Prefix &prefix = *prefix_it;
			Prefix prefix_anon(
				a49->Anonymize(IPAddr(prefix.addr(), NO_SCANNER)),
				prefix.len());
			Export(FOR_ALL, 
			       "topology: enterprise network", 
			       "%s (%s)",
			       prefix_anon.to_string().c_str(),
			       net->name().c_str());
			}

		const vector<EnterpriseSubnet *> &subnets = net->subnets();
		for ( subnet_it = subnets.begin(); 
		      subnet_it != subnets.end(); 
		      ++subnet_it )
			{
			const EnterpriseSubnet *subnet = *subnet_it;

			// Skip the subnet if it is broken up
			if ( ! subnet->break_up() )
				{
				const Prefix &prefix = subnet->prefix();
				Prefix prefix_anon(
					Anonymize(IPAddr(prefix.addr(), NO_SCANNER)),
					prefix.len());
				// Store the anonymized prefix in renumbered_subnet_prefixes
				renumbered_subnet_prefixes.push_back(prefix_anon);
				asubnet_by_prefix_anon.insert( 
					prefix_anon, 
					ianon_level2[0][prefix]);
				}
			}
		}

	// IMPORTANT: sort the prefixes to avoid leaking information
	sort(renumbered_subnet_prefixes.begin(), renumbered_subnet_prefixes.end());

	for ( prefix_it = renumbered_subnet_prefixes.begin(); 
	      prefix_it != renumbered_subnet_prefixes.end(); 
	      ++prefix_it )
		{
		const Prefix &prefix_anon = *prefix_it;
		Export(FOR_ALL, 
		       "topology: enterprise subnet", 
		       "%s",
		       prefix_anon.to_string().c_str());
		asubnet_by_prefix_anon[prefix_anon]->GenerateNotes();
		}

	a49->GenerateNotes();
	}

}  // namespace tcpmkpub
