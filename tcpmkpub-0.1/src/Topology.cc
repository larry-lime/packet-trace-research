#include <map>
#include <set>

using namespace std;

#include "Topology.h"

namespace tcpmkpub {

EnterpriseSubnet::EnterpriseSubnet(const Prefix &prefix)
	: prefix_(prefix),
	  gateway_(0),
	  break_up_(false),
	  export_notes_("")
	{
	}

EnterpriseSubnet *EnterpriseSubnet::BuildEnterpriseSubnet(
		const Prefix &prefix, 
		const char *gateway_str, 
		const char *broadcast_str,
		bool break_up, 
		const char *export_notes)
	{
	EnterpriseSubnet *subnet = new EnterpriseSubnet(prefix);

	if ( gateway_str && *gateway_str )
		{
		in_addr_t gateway = to_addr(gateway_str);
		if ( gateway > 0 )
			{
			subnet->set_gateway(gateway);

			if ( ! prefix.includes(gateway) )
				{
				delete subnet;
				throw Exception("Gateway %s not in subnet %s", 
					addr_to_string(gateway).c_str(),
					prefix.to_string().c_str());
				}
			}
		}

	// Extract broadcast addresses, separated by ","
	int pos_start, pos_end;
	int broadcast_str_len = strlen(broadcast_str);
	for ( pos_start = 0; 
	      pos_start < broadcast_str_len;
	      pos_start = pos_end + 1 )
		{
		for ( pos_end = pos_start; 
		      pos_end < broadcast_str_len; 
		      ++pos_end )
			{
			if ( broadcast_str[pos_end] == ',' )
				break;
			}
		in_addr_t addr = to_addr(broadcast_str + pos_start);
		if ( ! prefix.includes(addr) )
			{
			delete subnet;
			throw Exception("Broadcast addr %s not in subnet %s", 
				addr_to_string(addr).c_str(),
				prefix.to_string().c_str());
			}
		subnet->add_broadcast(addr);
		}

	subnet->set_break_up(break_up);
	subnet->set_export_notes(export_notes);

	return subnet;
	}

EnterpriseNetwork::~EnterpriseNetwork()
	{
	for ( unsigned int i = 0; i < subnets_.size(); ++i )
		delete subnets_[i];
	}

Topology::Topology()
	{
	}

Topology::~Topology()
	{
	for ( unsigned int i = 0; i < enterprise_networks_.size(); ++i )
		delete enterprise_networks_[i];
	}

void Topology::add_enterprise_network(EnterpriseNetwork *net)
	{
	// TODO: check if the network overlaps with any existing network
	enterprise_networks_.push_back(net);

	vector<Prefix>::const_iterator prefix_it;
	for ( prefix_it = net->prefixes().begin();
	      prefix_it != net->prefixes().end();
	      ++prefix_it )
		{
		enterprise_networks_by_prefix_.insert(*prefix_it, net);
		}
	}

void Topology::add_enterprise_subnet(EnterpriseSubnet *subnet)
	{
	PrefixVal<EnterpriseNetwork *> pv;
	if ( ! enterprise_networks_by_prefix_.look_up_prefix(
			subnet->prefix(), &pv) )
		{
		throw Exception("subnet %s does not belong to "
		                "any enterprise network",
		                subnet->prefix().to_string().c_str());
		}

	EnterpriseNetwork *net = pv.val;
	net->add_subnet(subnet);
	}


// Initialize the topology from local-policy/topology.anon
//
Topology *init_topology()
	{
	map<string, EnterpriseNetwork *> nets;
	vector<EnterpriseSubnet *> enterprise_subnets;

	// Keep track of processed subnet prefixes to ignore repeats
	set<Prefix> subnet_prefixes;

#	undef ENTERPRISE_NETWORK
#	undef ENTERPRISE_SUBNET

	// Cannot define "const bool BREAKUP = true;" because it would
	// cause a warning if BREAKUP is not used.
#	define BREAKUP 		true
#	define PRESERVE 	false

#	define ENTERPRISE_NETWORK(prefix_str, name)			\
		{							\
		EnterpriseNetwork *net = 0;				\
		if ( nets.find(name) == nets.end() )			\
			nets[name] = net = new EnterpriseNetwork(name);	\
		else							\
			net = nets[name];				\
		net->add_prefix(Prefix(prefix_str));			\
		}

#	define ENTERPRISE_SUBNET(prefix_str, mask_str,			\
			gateway, broadcast, 				\
			break_up, export_notes) 			\
		{							\
		Prefix prefix(prefix_str, mask_str);			\
		if ( subnet_prefixes.find(prefix) == subnet_prefixes.end() )\
			{						\
			subnet_prefixes.insert(prefix);			\
			EnterpriseSubnet *subnet = 			\
				EnterpriseSubnet::BuildEnterpriseSubnet(\
					prefix,				\
					gateway,			\
					broadcast,			\
					break_up,			\
					export_notes);			\
			enterprise_subnets.push_back(subnet);		\
			}						\
		}

#include "local-policy/topology.anon"

#	undef ENTERPRISE_NETWORK
#	undef ENTERPRISE_SUBNET

	if ( nets.empty() )
		{
		throw Exception("No ENTERPRISE_NETWORK is specified. "
		                "Please check local-policy/topology.anon.");
		}

	if ( enterprise_subnets.empty() )
		{
		throw Exception("No ENTERPRISE_SUBNET is specified. "
		                "Please check local-policy/topology.anon.");
		}

	Topology *topology = new Topology;

	for ( map<string, EnterpriseNetwork *>::const_iterator it = 
			nets.begin();
	      it != nets.end();
	      ++it )
		{
		topology->add_enterprise_network(it->second);
		}

	for ( vector<EnterpriseSubnet *>::const_iterator it = 
			enterprise_subnets.begin();
	      it != enterprise_subnets.end();
	      ++it )
		{
		topology->add_enterprise_subnet(*it);
		}

	return topology;
	}

}  // namespace tcpmkpub
