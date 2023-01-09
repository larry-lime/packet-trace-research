#ifndef ethernet_h
#define ethernet_h

#include <map>
using namespace std;

#include "Hash.h"

namespace tcpmkpub {

void init_mac_addr_anonymization(HashKey key);

DATA_PROCESSOR(anonymize_ethernet_pkt);
DATA_PROCESSOR(anonymize_ethernet_addr);
DATA_PROCESSOR(anonymize_ethernet_data);

}  // namespace tcpmkpub

#endif /* ethernet_h */
