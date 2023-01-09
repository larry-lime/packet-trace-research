#ifndef tcp_h
#define tcp_h

namespace tcpmkpub {

DATA_PROCESSOR(anonymize_tcp_pkt);
DATA_PROCESSOR(anonymize_tcp_options); 
DATA_PROCESSOR(TCPOPT_alert_and_replace_with_NOP);
DATA_PROCESSOR(renumber_tcp_timestamp);

}  // namespace tcpmkpub

#endif /* tcp_h */
