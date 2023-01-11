#ifndef icmp_h
#define icmp_h

namespace tcpmkpub {

DATA_PROCESSOR(anonymize_icmp_pkt);
DATA_PROCESSOR(anonymize_icmp_data);
DATA_PROCESSOR(recompute_icmp_checksum);

}  // namespace tcpmkpub

#endif /* icmp_h */
