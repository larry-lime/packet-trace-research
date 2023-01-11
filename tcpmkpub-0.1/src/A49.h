#ifndef A49_h
#define A49_h

#include "A50.h"
#include "PrefixTree.h"

// The difference between A50 and A49 is A49 has an extra list of
// "separatist" prefixes, and the separatist addresses are resolved
// separately after all other addresses are anonymized. The separatist
// prefixes are then settled at some untaken address space without
// considering preserving prefixes with other prefixes. For example,
// if 10.0.0.0 is a separatist prefix, and suppose 11.0.0.0 maps to
// 130.0.0.0 in A50. Ordinarily 10.0.0.0 should be mapped to
// 131.0.0.0, but in this case, it can be mapped to any untaken /8.
// 
// A49 allows some "well known" networks to be located separately,
// without exposing nearby addresses. This is particularly useful
// for anonymizing enterprise traces.
// 
// Address conflict happens when a "separatist" prefix is settled
// where a regular input maps to in A50, and can only occur when there
// are input addresses not included in the screening addresses provided
// for A49 initialization. Thus it is recommended that *all* input
// addresses be provided for screening before A49 settles separatists
// whenever possible.

namespace tcpmkpub {

class A49 : public IPAnonymizer
{
public:
	A49(HashKey key, 
		const vector<Prefix> &to_preserve, 
		const vector<Prefix> &separatists);
	~A49();

	void Preprocess(in_addr_t addr);

	// Note: be ready to catch exception A49_AnonymizationDelayed
	in_addr_t Anonymize(IPAddr const & input);

	void GenerateNotes();

protected:
	void SettleSeparatists();
	Prefix SettleSeparatist(const Prefix &prefix);
	bool UnoccupiedOutput(const Prefix &prefix);

	HashKey key;
	A50 *a50;

	vector<Prefix> separatists;
	bool separatists_settled;

	// address space belongs to the separatists
	PrefixTree<Prefix> separatist_tree;

	enum OutputPrefixType
		{
		REGULAR_A50,
		SEPARATIST,
		};

	// address space already taken (used when settling the separatists)
	PrefixTree<OutputPrefixType> output_tree;
};

// An exception class raised when a regular and a separatist addresses are
// mapped to the same output address.
class A49_OutputAddrConflict : public Exception
{
public:
	A49_OutputAddrConflict(in_addr_t arg_output, in_addr_t arg_input)
		: Exception("A49 output address conflict "
			"for input addr %s at output %s",
			addr_to_string(arg_input).c_str(), 
			addr_to_string(arg_output).c_str()),
		  output(arg_output), 
		  input(arg_input) 
		{
		}

protected:
	in_addr_t output;
	in_addr_t input;
};

}  // namespace tcpmkpub

#endif  // A49_h
