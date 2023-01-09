// The prefix-preserving IP address anonymization code is largely
// based on (and sometimes directly copied from) Eddie Kohler's
// ipsumdump-1.20 code, per:
//
//	http://www.icir.org/kohler/ipsumdump/

#ifndef A50_h
#define A50_h

#include "Prefix.h"
#include "Hash.h"
#include "IPAddr.h"

#include <vector>
using namespace std;

namespace tcpmkpub {

class A50 : public IPAnonymizer
{
public:
	A50(HashKey key, const vector<Prefix> &to_preserve);
	~A50();

	in_addr_t Anonymize(IPAddr const & input);
	void GenerateNotes() { /* do nothing */ }

	void sanity_check() const;

protected:
	void preserve_prefix(in_addr_t input, int num_bits);

	struct Node {
		in_addr_t input;
		in_addr_t output;
		Node* child[2];
	};

	Node* new_node();
	Node* new_node_block();
	void free_node(Node*);

	Node* find_node(in_addr_t);
	Node* make_peer(in_addr_t input, Node *peer);
	in_addr_t make_output(in_addr_t input, 
		int swivel, in_addr_t peer_output) const;
	in_addr_t hash_a50(in_addr_t input, int swivel) const;
	void sanity_check(Node *n) const;

protected:
	HashKey key;

	// The root of prefix preserving mapping tree.
	Node* root;

	// A node pool for new_node.
	Node* next_free_node;
	vector<Node*> blocks;
};

}  // namespace tcpmkpub

#endif // A50_h
