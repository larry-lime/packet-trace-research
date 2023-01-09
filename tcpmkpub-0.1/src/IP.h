#ifndef ip_h
#define ip_h

#include "Hash.h"

namespace tcpmkpub {

DATA_PROCESSOR(register_ip_addr);
DATA_PROCESSOR(anonymize_ip_addr);

DATA_PROCESSOR(anonymize_ip_pkt);
DATA_PROCESSOR(anonymize_ip_options);
DATA_PROCESSOR(IPOPT_check_router_alert_zero);
DATA_PROCESSOR(IPOPT_anonymize_record_route);
DATA_PROCESSOR(IPOPT_alert_and_replace_with_NOP);
DATA_PROCESSOR(anonymize_ip_data);

// void init_ip_addr_anonymization(HashKey key);
// in_addr_t anonymize_ip_addr(in_addr_t addr);

}  // namespace tcpmkpub

#endif /* ip_h */
