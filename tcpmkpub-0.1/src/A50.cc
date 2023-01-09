#include <stdio.h>
#include <cassert>

#include "common.h"
#include "Hash.h"
#include "A50.h"

namespace tcpmkpub {

A50::A50(HashKey arg_key, const vector<Prefix> &to_preserve)
	{
	root = next_free_node = 0;
	memcpy((void *) key, arg_key, sizeof(key));
	for ( int i = 0; i < (int) to_preserve.size(); ++i )
		preserve_prefix(to_preserve[i].addr(), to_preserve[i].len());
	sanity_check();
	}

A50::~A50()
	{
	for ( unsigned int i = 0; i < blocks.size(); ++i )
		delete [] blocks[i];

	blocks.clear();
	}

// NOTE: if there are multiple prefix to preserve, they should be
// provided with non-indecreasing length.
void A50::preserve_prefix(in_addr_t input, int num_bits)
	{
	// DEBUG_MSG(fmt("%s/%d\n", dotted_addr(input), num_bits));

	// Sanitize input.
	input = input & first_n_bit_mask(num_bits);

	Node* n = find_node(input);

	assert((0xFFFFFFFFU >> 1) == 0x7FFFFFFFU);
	in_addr_t suffix_mask = (0xFFFFFFFFU >> num_bits);
	in_addr_t prefix_mask = ~suffix_mask;
	n->output = (input & prefix_mask) | (n->output & suffix_mask);
	}

void A50::sanity_check() const
	{
	sanity_check(root);
	}

void A50::sanity_check(Node *n) const
	{
	if ( ! n )
		return;

	if ( n->child[0] && n->child[1] )
		{
		// Rule 1: input and output should have the same swivel
		int input_swivel = 
			bi_ffs(n->child[0]->input ^ n->child[1]->input);
		int output_swivel = 
			bi_ffs(n->child[0]->output ^ n->child[1]->output);

		if ( input_swivel != output_swivel )
			internal_error("not prefix preserving");

		// Rule 2: there's a first-born child that has
		// identical input/output as the parent
		int first_born = -1;
		if ( n->input == n->child[0]->input )
			first_born = 0;
		else if ( n->input == n->child[1]->input )
			first_born = 1;
		else
			internal_error("no first-born child");

		if ( n->output != n->child[first_born]->output )
			internal_error("output mismatch");

		// recursive sanity check on both children
		sanity_check(n->child[0]);
		sanity_check(n->child[1]);
		}
	else
		{
		if ( n->child[0] || n->child[1] )
			internal_error("missing one child");
		}
	}

in_addr_t A50::Anonymize(IPAddr const & a)
	{
	return find_node(a.addr())->output;
	}

A50::Node* A50::new_node_block()
	{
	assert(! next_free_node);

	int block_size = 1024;
	Node* block = new Node[block_size];
	if ( ! block )
		internal_error("out of memory!");

	blocks.push_back(block);

	for ( int i = 1; i < block_size - 1; ++i )
		block[i].child[0] = &block[i+1];

	block[block_size - 1].child[0] = 0;
	next_free_node = &block[1];

	return &block[0];
	}

inline A50::Node* A50::new_node()
	{
	if ( next_free_node )
		{
		Node* n = next_free_node;
		next_free_node = n->child[0];
		return n;
		}
	else
		return new_node_block();
	}

inline void A50::free_node(Node *n)
	{
	n->child[0] = next_free_node;
	next_free_node = n;
	}

in_addr_t A50::hash_a50(in_addr_t a, int swivel) const
	{
	// Generate the pseudo-random bits for the last (32 - swivel) bits.
	// 
	// For each bit, we decide whether to flip the bit from the
	// input by hashing the prefix before the bit, so that the
	// flipping does not depend on the order of inputs given, and
	// with the same hash key, we can have a consistent mapping.
	// For details, see: J. Xu et.al.: "On the design and
	// performance of prefix-preserving IP traffic trace anonymization"

	struct { in_addr_t prefix; int len; } prefix;

	in_addr_t output = 0;

	for ( int i = swivel; i < 32; ++i )
		{
		// Note: apply htonl to insure the layout to be the
		// same on machines with different byte order

		prefix.prefix = htonl(a & first_n_bit_mask(i));
		prefix.len = htonl(i);

		u_char digest[16];
		hmac_md5(HASH_TYPE_A50, key, 
			sizeof(prefix), (u_char*)(&prefix), digest);
		int flip = digest[0] & 1;

		in_addr_t bit_mask = 1 << (31-i);
		output = output | ((flip << (31-i)) ^ (a & bit_mask));
		}

	return output;
	}

in_addr_t A50::make_output(in_addr_t input, int swivel, in_addr_t peer_output) const
	{
	// -A50 anonymization
	// swivel should be between 1 and 32.
	// We know the first swivel bits from peer_output: 
	// bits up to swivel are unchanged; bit swivel is flipped.
	in_addr_t known_part =
		((peer_output >> (32 - swivel)) ^ 1) << (32 - swivel);

	// Remainder of bits are computed with hash_a50
	return known_part | hash_a50(input, swivel);
	}

A50::Node* A50::make_peer(in_addr_t a, Node* n)
	{
	// Become a peer.
	// Algorithm: create two nodes, the two peers.  Leave orig node as
	// the parent of the two new ones.

	Node* down[2];

	if ( ! (down[0] = new_node()) )
		return 0;

	if ( ! (down[1] = new_node()) )
		{
		free_node(down[0]);
		return 0;
		}

	// swivel is first bit 'a' and 'old->input' differ.
	int swivel = bi_ffs(a ^ n->input);

	// bitvalue is the value of that bit of 'a'.
	int bitvalue = (a >> (32 - swivel)) & 1;

	down[bitvalue]->input = a;
	down[bitvalue]->output = make_output(a, swivel, n->output);
	down[bitvalue]->child[0] = down[bitvalue]->child[1] = 0;

	*down[1 - bitvalue] = *n;	// copy orig node down one level

#if 0
	Does not seem to be necessary. -RP
	n->input = down[1]->input;	// NB: 1s to the right (0s to the left)
	n->output = down[1]->output;
#endif

	n->child[0] = down[0];		// point to children
	n->child[1] = down[1];

	return down[bitvalue];
	}

A50::Node* A50::find_node(in_addr_t a)
	{
	if ( ! root )
		{
		root = new_node();
		root->input = a;
		root->output = hash_a50(a, 0);
		root->child[0] = root->child[1] = 0;

		return root;
		}

	// Straight from tcpdpriv.
	Node* n = root;
	while ( n )
		{
		if ( n->input == a )
			return n;

		if ( ! n->child[0] )
			n = make_peer(a, n);

		else
			{
			// swivel is the first bit in which the two children
			// differ.
			int swivel =
				bi_ffs(n->child[0]->input ^ n->child[1]->input);

			if ( bi_ffs(a ^ n->input) < swivel )
				// Input differs earlier.
				n = make_peer(a, n);

			else if ( a & (1 << (32 - swivel)) )
				n = n->child[1];

			else
				n = n->child[0];
			}
		}

	internal_error("out of memory!");
	return 0;
	}

}  // namespace tcpmkpub
