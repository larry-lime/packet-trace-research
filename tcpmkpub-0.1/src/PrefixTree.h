#ifndef prefixtree_h
#define prefixtree_h

#include <vector>
using namespace std;

#include "common.h"
#include "Prefix.h"

namespace tcpmkpub {

#define next_bit(node, addr)	(((addr) >> (31 - (node)->prefix.len())) & 1)

template <class T> 
struct ValNode 
{ 
	T val; 
	ValNode(const T &v) : val(v) {}
};

template <class T>
struct PrefixTreeNode
{
	Prefix prefix;
	ValNode<T> *v;
	PrefixTreeNode<T> *child[2];
};

template <class T>
struct PrefixVal
{
	Prefix prefix;
	T val;
	PrefixVal() {}
	PrefixVal(const Prefix &p, const T &v) : prefix(p), val(v) {}
};

template <class T> 
class PrefixTree
{
public:
	typedef PrefixTreeNode<T> Node;

	PrefixTree()	{ root = 0; }
	~PrefixTree()	{}

	void insert(const Prefix &prefix, const T &val)
		{ root = insert(root, prefix, val); }

	// Whether there is a prefix that includes addr
	bool contains(in_addr_t addr)
		{
		for ( Node *node = root; 
			node && node->prefix.includes(addr); 
			node = node->child[next_bit(node, addr)])
			{
			if ( node->v )
				return true;
			}
		return false;
		}

	// Returns true if a prefix is found to contain addr.  When
	// there are multiple such prefix, pv will be the most specific
	// one. 
	bool look_up_prefix(in_addr_t addr, PrefixVal<T> *pv)
		{
		return look_up_prefix(Prefix(addr), pv);
		}

	bool look_up_prefix(const Prefix &prefix, PrefixVal<T> *pv)
		{
		Node *n = look_up_prefix(root, prefix);
		if ( n && n->v )
			{
			pv->prefix = n->prefix;
			pv->val = n->v->val;
			return true;
			}
		else
			return false;
		}

	// Returns all <prefix, val> pairs with <prefix> including
	// addr
	bool look_up_all(in_addr_t addr, vector< PrefixVal<T> > *pv_list)
		{
		bool any = false;
		for ( Node *node = root; 
		      node && node->prefix.includes(addr); 
		      node = node->child[next_bit(node, addr)])
			{
			if ( node->v )
				{
				any = true;
				pv_list->push_back(
					PrefixVal<T>(node->prefix, 
					             node->v->val));
				}
			}

		return any;
		}

	const T &operator[](const Prefix &prefix)
		{
		Node *n = look_up_prefix(root, prefix);
		if ( n && n->v )
			return n->v->val;
		throw Exception("cannot find prefix %s in operator[]", 
			prefix.to_string().c_str());
		}

	// Whether the tree contains value on any sub-prefix of the given prefix
	bool contains_subprefix_of(const Prefix &prefix)
		{
		Node *n = root;
		while ( n && n->prefix.includes(prefix) ) 
			{
			if ( prefix.includes(n->prefix) )
				return true;
			n = n->child[next_bit(n, prefix.addr())]; 
			}
		return ( n && prefix.includes(n->prefix) );
		}

#if 0
	bool find_subprefixes(const Prefix &prefix, vector< PrefixVal<T> > *pv_list)
		{
		Node *n = look_up_prefix(root, prefix);
		return add_subprefixes(n, prefix, pv_list);
		}
#endif

protected:
	Node *new_node(const Prefix &prefix)
		{
		// fprintf(stderr, "new_node: %s\n", 
		// 	prefix.to_string().c_str());
		Node *node = new Node;
		node->prefix = prefix;
		node->v = 0;
		node->child[0] = node->child[1] = 0;
		return node;
		}

	Node *make_peer(Node *peer, const Prefix &prefix, const T &val)
		{
		// We know that:
		// 1) <peer> does NOT include <prefix>
		// 2) the parent of <peer>, if exists, does include <prefix>

		Node *n;

		if ( prefix.includes(peer->prefix) )
			{
			n = new_node(prefix);
			n->v = new ValNode<T>(val);
			int peer_bit = next_bit(n, peer->prefix.addr());
			n->child[peer_bit] = peer;
			}
		else
			{
			// find out the common prefix
			int swivel = bi_ffs(prefix.addr() ^ peer->prefix.addr());
			n = new_node(Prefix(prefix.addr(), swivel - 1));
			int peer_bit = next_bit(n, peer->prefix.addr());
			n->child[peer_bit] = peer;
			n->child[1 - peer_bit] = new_node(prefix);
			n->child[1 - peer_bit]->v = new ValNode<T>(val);
			}

		return n;
		}

	Node *insert(Node *node, const Prefix &prefix, const T &val)
		{
		if ( ! node )
			{
			Node *node = new_node(prefix);
			node->v = new ValNode<T>(val);
			return node;
			}
	
		if ( ! node->prefix.includes(prefix) )
			return make_peer(node, prefix, val);
	
		if ( node->prefix.len() == prefix.len() )
			{
			if ( ! node->v )
				node->v = new ValNode<T>(val);
			else
				node->v->val = val;
			return node;
			}
	
		int nbit = next_bit(node, prefix.addr());
		node->child[nbit] = insert(node->child[nbit], prefix, val);
	
		return node;
		}

	// Returns the lowest node (with value) that contains the given prefix
	Node *look_up_prefix(Node *node, const Prefix &prefix)
		{
		if ( ! node )
			return 0;

		// fprintf(stderr, "look_up_prefix: %s at node %s\n",
		// 	prefix.to_string().c_str(),
		// 	node->prefix->to_string().c_str());

		if ( ! node->prefix.includes(prefix) )
			return 0;

		// fprintf(stderr, "look_further: %s at node %s\n",
		// 	prefix.to_string().c_str(),
		// 	node->prefix->to_string().c_str());

		Node *n = look_up_prefix(
			node->child[next_bit(node, prefix.addr())], 
			prefix);

		if ( n )
			return n;

		return node->v ? node : 0;
		}

#if 0
	bool add_subprefixes(Node *n, 
	                     const Prefix &prefix, 
	                     vector< PrefixVal<T> > *pv_list)
		{
		if ( ! n )
			return false;

		if ( prefix.includes(n->prefix) && n->v )
			{
			pv_list->push_back(PrefixVal<T>(n->prefix, n->v->val));
			return true;
			}

		if ( n->prefix.len() >= prefix.len() &&
		     ! n->prefix.includes(prefix) )
			return false;

		bool added = false;
		if ( add_subprefixes(n->child[0], prefix, pv_list) )
			added = true;
		if ( add_subprefixes(n->child[1], prefix, pv_list) )
			added = true;
		return added;
		}
#endif

	Node *root;
};

}  // namespace tcpmkpub

#endif /* prefixtree_h */
