#include <stdio.h>

#include "Anon.h"
#include "A49.h"

namespace tcpmkpub {

A49::A49(HashKey arg_key, 
		const vector<Prefix> &to_preserve, 
		const vector<Prefix> &arg_separatists)
	{
	memcpy((void *) key, arg_key, sizeof(key));
	a50 = new A50(key, to_preserve);

	// We will need to settle the bigger separatists before the
	// smaller ones, so we first sort them by length.
	sort_prefixes_by_len(arg_separatists, separatists);

	for ( int i = 0; i < (int) separatists.size(); ++i )
		{
		// Make a sanity check: separatists must not contain
		// each other.
		PrefixVal<Prefix> pv;
		if ( separatist_tree.look_up_prefix(separatists[i], &pv) )
			{
			string prefix_a = separatists[i].to_string();
			string prefix_b = pv.val.to_string();
			Alert("enclosing prefixes: %s < %s",
				prefix_a.c_str(), prefix_b.c_str());
			continue;
			}
		separatist_tree.insert(separatists[i], true);
		}

	separatists_settled = false;
	}

A49::~A49()
	{
	delete a50;
	}

void A49::Preprocess(in_addr_t addr)
	{
	if ( separatists_settled )
		{
		internal_error("%.6f A49 preprocess must happen before any "
		               "address anonymization", network_time);
		}

	// If addr is outside separatist prefixes, find out to where it is 
	// mapped by the A50 algorithm, and remember the output in 
	// output_tree.

	PrefixVal<Prefix> pv;
	if ( ! separatist_tree.look_up_prefix(addr, &pv) )
		{
		// The scanner ID doesn't matter here because 
		// we only care about prefixes.
		in_addr_t b = a50->Anonymize(IPAddr(addr, NO_SCANNER));
		DebugMsg("A49 preprocess: %s -> %s", 
		         addr_to_string(addr).c_str(),
		         addr_to_string(b).c_str());
		output_tree.insert(Prefix(b, 32), REGULAR_A50);
		}
	}

in_addr_t A49::Anonymize(IPAddr const & addr)
	{
	if ( ! separatists_settled )
		{
		ASSERT(! in_preprocessing);
		SettleSeparatists();	
		}

	in_addr_t a = addr.addr();

	PrefixVal<Prefix> pv;
	in_addr_t prefix = 0;
	in_addr_t prefix_mask = 0;
	bool is_separatist = false;
	if ( separatist_tree.look_up_prefix(a, &pv) )
		{
		is_separatist = true;
		if ( ! separatists_settled )
			internal_error("separatists not settled");
		prefix = pv.val.addr();
		prefix_mask = pv.prefix.mask();
		}

	in_addr_t b = 
		(prefix & prefix_mask) | (a50->Anonymize(addr) & ~prefix_mask);

	// A sanity check on the output prefix
	// If the output is already in the output_tree, check if the types
	// (regular vs. separatist) match.
	PrefixVal<OutputPrefixType> pv2;
	if ( output_tree.look_up_prefix(b, &pv2) )
		{
		OutputPrefixType ty = pv2.val;
		if ( ( is_separatist && ty == REGULAR_A50 ) ||
		     ( ! is_separatist && ty == SEPARATIST ) )
			{
			throw A49_OutputAddrConflict(b, a);
			}
		}
	
	return b;
	}

bool A49::UnoccupiedOutput(const Prefix &prefix)
	{
	PrefixVal<OutputPrefixType> pv;
	return ! output_tree.look_up_prefix(prefix, &pv) &&
	       ! output_tree.contains_subprefix_of(prefix);
	}

Prefix A49::SettleSeparatist(const Prefix &prefix)
	{
	if ( prefix.len() == 0 )
		throw Exception("trying to settle zero-length prefix: %s",
			prefix.to_string().c_str());

	// Return the prefix itself if it is not occupied by A50 outputs
	if ( UnoccupiedOutput(prefix) )
		return prefix;

	Alert("cannot settle separatist %s as itself",
	      prefix.to_string().c_str()); 

	// Next try a pseudo-random prefix that is hashed from prefix
	struct { in_addr_t prefix; int len; } hash_data =
		{ htonl(prefix.addr()), htonl(prefix.len()) };
	in_addr_t h_prefix;

	u_char digest[16];
	hmac_md5(HASH_TYPE_A49_SEPARATIST, 
	         key, sizeof(hash_data), (u_char*)(&hash_data), digest);
	memcpy((void *) &h_prefix, digest, sizeof(h_prefix));
	h_prefix = ntohl(h_prefix) & prefix.mask();
		
	Prefix hashed_prefix(h_prefix, prefix.len());
	if ( UnoccupiedOutput(hashed_prefix) )
		{
		// Good! We will use the hashed_prefix then
		return hashed_prefix;
		}

	Alert("cannot settle separatist %s with hashing",
	      prefix.to_string().c_str()); 

	// Finally we will just try all non-zero prefixes one-by-one.
	// TODO: this is clearly inefficient (but hopefully we will not get into 
	// such a situation.
	//
	in_addr_t prefix_inc = 1 << (32 - prefix.len());
	for ( in_addr_t prefix_addr = prefix_inc; 
	      prefix_addr <= prefix.mask(); 
	      prefix_addr += prefix_inc )
		{
		Prefix output(prefix_addr, prefix.len());
		if ( UnoccupiedOutput(output) )
			return output;
		}

	throw Exception("cannot settle separatist %s", 
		prefix.to_string().c_str());
	}

void A49::SettleSeparatists()
	{
	a50->sanity_check();

	// Note that the separatists are already sorted by prefix length.
	for ( int i = 0; i < (int) separatists.size(); ++i )
		{
		const Prefix &prefix = separatists[i];
		Prefix output = SettleSeparatist(prefix);

		// Let's put it into the mapping
		separatist_tree.insert(prefix, output);
		// And claim the output space
		output_tree.insert(output, SEPARATIST);
		}

	separatists_settled = true;
	}

void A49::GenerateNotes()
	{
	for ( int i = 0; i < (int) separatists.size(); ++i )
		{
		const Prefix &prefix = separatists[i];
		Prefix output = separatist_tree[prefix];

		Note("A49 network: %s -> %s",
		     prefix.to_string().c_str(),
		     output.to_string().c_str());

		Export(FOR_ALL, 
		       "topology: prefix-independent network", 
		       "%s", output.to_string().c_str());
		}
	}

}  // namespace tcpmkpub
