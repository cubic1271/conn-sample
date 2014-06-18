#ifndef _SAMPLER_H
#define _SAMPLER_H

#define BLOOM_NUM_ELEMENTS (1000000)
#define BLOOM_TARGET_PROB  (0.0001)

#define RATE_FIXED_DECREASE (0.40)
#define RATE_FIXED_INCREASE (2.50)

#define IP_PROTO_ICMP      (1)
#define IP_PROTO_TCP       (6)
#define IP_PROTO_UDP       (17)


bool is_usable_packet(pcap_pkthdr *pkt_header, const uint8_t *pkt_buffer);
unsigned int build_connection_hash(pcap_pkthdr *pkt_header, const uint8_t *pkt_buffer);

#endif

