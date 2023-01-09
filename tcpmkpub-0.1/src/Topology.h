#ifndef topology_h
#define topology_h

#include "Prefix.h"
#include "PrefixTree.h"

namespace tcpmkpub {

class EnterpriseSubnet
{
public:
	explicit EnterpriseSubnet(const Prefix &prefix);

	EnterpriseSubnet(const EnterpriseSubnet &subnet)
		: prefix_(subnet.prefix()), 
		  gateway_(subnet.gateway()),
		  broadcast_(subnet.broadcast()),
		  break_up_(subnet.break_up()),
		  export_notes_(subnet.export_notes()) {}

	static EnterpriseSubnet *BuildEnterpriseSubnet(
		const Prefix &prefix, 
		const char *gateway, 
		const char *broadcast,
		bool break_up, 
		const char *export_notes);

	const Prefix &prefix() const	{ return prefix_; }

	in_addr_t gateway() const 	{ return gateway_; }
	void set_gateway(in_addr_t x)	{ gateway_ = x; }

	const vector<in_addr_t> &broadcast() const { return broadcast_; }
	void add_broadcast(in_addr_t x) { broadcast_.push_back(x); }

	const bool break_up() const	{ return break_up_; }
	void set_break_up(bool x)	{ break_up_ = x; }

	const string &export_notes() const { return export_notes_; }
	void set_export_notes(const string &x) { export_notes_ = x; }

protected:
	Prefix prefix_;
	in_addr_t gateway_;
	vector<in_addr_t> broadcast_;
	bool break_up_;
	string export_notes_;
};

class EnterpriseNetwork 
{
public:
	explicit EnterpriseNetwork(const char *name)
		: name_(name) { }
	~EnterpriseNetwork();

	const string &name() const	{ return name_; }

	const vector<Prefix> &prefixes() const 	{ return prefixes_; }
	void add_prefix(Prefix const &prefix) 	{ prefixes_.push_back(prefix); }

	const vector<EnterpriseSubnet *> &subnets() const { return subnets_; }
	void add_subnet(EnterpriseSubnet *subnet) { subnets_.push_back(subnet); }

protected:
	string name_;
	vector<Prefix> prefixes_;
	vector<EnterpriseSubnet *> subnets_;
};

class Topology
{
public:
	Topology();
	~Topology();

	// Add an enterprise network (i.e. a set of prefixes) to the topology. 
	// The enterprise network must have its complete set of prefixes added
	void add_enterprise_network(EnterpriseNetwork *net);

	// Add an enterprise subnet to the topology.
	// A subnet must be added after its enclosing network. 
	void add_enterprise_subnet(EnterpriseSubnet *subnet);

	const vector<EnterpriseNetwork *> &enterprise_networks() const 
		{ return enterprise_networks_; }

protected:
	PrefixTree<EnterpriseNetwork *> enterprise_networks_by_prefix_;
	vector<EnterpriseNetwork *> enterprise_networks_;
};

// Initialize topology from topology.anon
Topology *init_topology();

}  // namespace tcpmkpub

#endif  // topology_h
