#ifndef fieldtype_h
#define fieldtype_h

namespace tcpmkpub {

#define FIELD(name, len, processor)		name,
#define PUTOFF_FIELD(name, len, processor)	name,
#define PICKUP_FIELD(name, len, processor)	/* nothing */
#define CASE(name, index, len, processor)	name,
#define DEFAULT_CASE(name, len, processor)	name,

enum FieldType {
#include "policy/ether.anon"
#include "policy/ether-data.anon"
#include "policy/arp.anon"
#include "policy/ip.anon"
#include "policy/ip-option.anon"
#include "policy/ip-frag.anon"
#include "policy/ip-data.anon"
#include "policy/icmp.anon"
#include "policy/icmp-context.anon"
#include "policy/icmp-data.anon"
#include "policy/icmp-echo.anon"
#include "policy/icmp-ireq.anon"
#include "policy/icmp-maskreq.anon"
#include "policy/icmp-paramprob.anon"
#include "policy/icmp-redirect.anon"
#include "policy/icmp-routersolicit.anon"
#include "policy/icmp-tstamp.anon"
#include "policy/tcp-option.anon"
#include "policy/tcp.anon"
#include "policy/udp.anon"
};

#undef FIELD
#undef PUTOFF_FIELD
#undef PICKUP_FIELD
#undef CASE
#undef DEFAULT_CASE

}  // namespace tcpmkpub

#endif /* fieldtype_h */
