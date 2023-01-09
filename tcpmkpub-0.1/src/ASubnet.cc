// Anonymization of subnet addresses.
#include "Anon.h"
#include "IP.h"
#include "Topology.h"
#include "ASubnet.h"
#include "AEnt.h"

namespace tcpmkpub {

ASubnet::ASubnet(HashKey arg_key, 
                 AEnt *arg_aent, 
                 const EnterpriseSubnet *arg_subnet, 
                 int arg_flags)
	: aent(arg_aent), 
	  subnet(arg_subnet), 
          flags(arg_flags),
          prefix(arg_subnet->prefix()) 
	{
	copy_hashkey(const_cast<u_char *>(key), arg_key);

	in_addr_t suffix_mask = ~prefix.mask();
	if ( flags & PRESERVE_GATEWAY && prefix.includes(subnet->gateway()) )
		suffix_to_preserve.insert(subnet->gateway() & suffix_mask);
	if ( flags & PRESERVE_BROADCAST ) 
		{
		const vector<in_addr_t> &b = subnet->broadcast();
		for ( int i = 0; i < (int) b.size(); ++i )
			{
			if ( prefix.includes(b[i]) )
				suffix_to_preserve.insert(b[i] & suffix_mask);
			}
		}
	}

in_addr_t ASubnet::Anonymize(IPAddr const & input)
	{
	in_addr_t addr = input.addr();
	if ( ! prefix.includes(addr) )
		throw Exception("address %s not in subnet %s",
			addr_to_string(addr).c_str(),
			prefix.to_string().c_str());

	in_addr_t prefix_part = (addr & prefix.mask());
	in_addr_t suffix = (addr & ~prefix.mask());
	if ( suffix_to_preserve.find(suffix) != suffix_to_preserve.end() )
		return (prefix_part | suffix);

	in_addr_t suffix_a;

	struct { in_addr_t addr; int len; in_addr_t scanner; } hash_seed =
		{ 
		htonl(prefix.addr()), 
		htonl(prefix.len()), 
		htonl(input.scanner()),
		};

	for(;;) 
		{
		suffix_a = prp_md5(HASH_TYPE_AINTRASUBNET, key, 
			sizeof(hash_seed), (const u_char *) &hash_seed, 
			32 - prefix.len(), suffix);
		if ( suffix_to_preserve.find(suffix_a) == suffix_to_preserve.end() )
			break;
		suffix = suffix_a;
		}

	return prefix_part | suffix_a;
	}

void ASubnet::GenerateNotes()
	{
	in_addr_t subnet_anon = aent->Anonymize(IPAddr(prefix.addr(), NO_SCANNER));
	string subnet_anon_str = Prefix(subnet_anon, prefix.len()).to_string();

	in_addr_t gateway = subnet->gateway();
	if ( gateway != 0 )
		{
		in_addr_t gateway_anon = 
			aent->Anonymize(IPAddr(gateway, NO_SCANNER)); 
		Export(FOR_ALL, 
		       "topology: gateway address", 
		       "%s -> %s", 
		       subnet_anon_str.c_str(),
		       addr_to_string(gateway_anon).c_str());
		}

	for ( vector<in_addr_t>::const_iterator it = subnet->broadcast().begin(); 
			it != subnet->broadcast().end(); ++it )
		{ 
		in_addr_t broadcast_addr_anon = 
			aent->Anonymize(IPAddr(*it, NO_SCANNER));
		Export(FOR_ALL, 
		       "topology: broadcast address", 
		       "%s -> %s", 
		       subnet_anon_str.c_str(),
		       addr_to_string(broadcast_addr_anon).c_str());
		}
	}

ASubnetGroup::ASubnetGroup(HashKey arg_key, 
		string arg_name, const vector<Prefix> &arg_prefixes)
	: name(arg_name)
	{
	copy_hashkey(const_cast<u_char *>(key), arg_key);
	nets = arg_prefixes;
	}

void ASubnetGroup::add_subnet(const Prefix &prefix)
	{
	subnets.push_back(prefix);
	}

void ASubnetGroup::finalize()
	{
	vector<Prefix> available_prefixes = nets;
	settle(0, available_prefixes);
	finalized = true;
	Note("network \"%s\": %d addresses are open after subnets are settled",
		name.c_str(), available_addresses.size());
	}

void ASubnetGroup::settle(int prefix_len, 
		vector<Prefix>& available_prefixes)
	{
	vector<Prefix> A;
	for ( int i = 0; i < (int) available_prefixes.size(); )
		if ( (int) available_prefixes[i].len() == prefix_len )
			{
			A.push_back(available_prefixes[i]);
			available_prefixes[i] = available_prefixes.back();
			available_prefixes.pop_back();
			}
		else
			++i;

	vector<Prefix> S;
	for ( int i = 0; i < (int) subnets.size(); ++i )
		if ( (int) subnets[i].len() == prefix_len )
			S.push_back(subnets[i]);

	for( int i = 0; i < (int) S.size(); ++i )
		{
		if ( A.empty() )
			{
			throw Exception("cannot settle all subnets on prefix length %d", 
				prefix_len);
			}

		const Prefix &p = S[i];
		int n = A.size();
		int k = hash_prefix(HASH_TYPE_AINTERSUBNET, key, p, n);
		Prefix p2 = A[k];
		subnet_tree.insert(p, p2);
		Note("subnet %s -> %s",
		     p.to_string().c_str(), 
		     p2.to_string().c_str());
		A[k] = A.back();
		A.pop_back();
		}

	if ( prefix_len < 32 )
		{
		vector<Prefix> next_available_prefixes = available_prefixes;
		for ( int i = 0; i < (int) A.size(); ++i )
			{
			const Prefix &p = A[i];
			next_available_prefixes.push_back(
				Prefix(p.addr(), p.len() + 1));
			next_available_prefixes.push_back(
				Prefix(p.addr() | ~p.mask(), p.len() + 1));
			}
		settle(prefix_len + 1, next_available_prefixes);
		}
	else
		{
		// Remember all remaining available addresses
		available_addresses.clear();
		for ( int i = 0; i < (int) A.size(); ++i )
			available_addresses.push_back(A[i].addr());
		}
	}

in_addr_t ASubnetGroup::pick_available_addr(in_addr_t addr)
	{
	// For addresses not belonging to any subnet
	if ( other_addresses.find(addr) != other_addresses.end() )
		return other_addresses[addr];

	in_addr_t suffix = addr & 0xff;
	bool keep_suffix = (suffix == 0 || suffix == 0xff || suffix == 1); 

	list<in_addr_t>::iterator it;
	for ( it = available_addresses.begin(); 
	      it != available_addresses.end(); 
	      ++it )
		{
		in_addr_t a = *it;
		in_addr_t suffix_a = a & 0xff;
		bool special_suffix = 
			(suffix_a == 0 || suffix_a == 0xff || suffix_a == 1); 
		if ( ( ! keep_suffix && ! special_suffix ) || 
		     ( keep_suffix && suffix == suffix_a ) )
			// got it
			{
			Export(FOR_ALL, 
			       "unallocated enterprise address", 
			       "%s",
			       addr_to_string(a).c_str());
			other_addresses[addr] = a;
			available_addresses.erase(it);
			return a;
			}
		}

	Alert("Cannot find an available address for %s",
		addr_to_string(addr).c_str());
	return 0;
	}
	
in_addr_t ASubnetGroup::Anonymize(IPAddr const & input)
	{
	if ( ! finalized )
		throw Exception("ASubnetGroup %s not finalized",
			name.c_str());

	in_addr_t addr = input.addr();
	PrefixVal<Prefix> pv;
	if ( ! subnet_tree.look_up_prefix(addr, &pv) )
		{
		Alert("address %s not in any subnet",
			addr_to_string(addr).c_str());
		return pick_available_addr(addr);
		}

	// replace the subnet prefix of addr
	return (pv.val.addr() & pv.prefix.mask()) | (addr & ~pv.prefix.mask());
	}

void ASubnetGroup::GenerateNotes()
	{
	// Do nothing, because notes about enterprise networks are already 
	// generated in AEnt::GenerateNotes().
	}

}  // namespace tcpmkpub
