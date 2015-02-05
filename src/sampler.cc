#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "murmurhash2.h"
#include "bloom.h"
#include "sampler.h"

#define PKTBUF_SZ (8192)

static unsigned int _seed;
static bool _done = false;

void usage()
{
    // while ((c = getopt (argc, argv, "d:hi:r:s:t:E:P:S:")) != -1)
    printf("Usage: sampler [-d drop_timeout_msec] -h -i [interface] -r [fixed_sampling_rate] -s [integer_seed] -t [execution_time_sec] -E [expected_connections] -P [error_probability] -S [synthetic_delay_usec] -w [trace_output_file]\n");
    printf("This program offers two modes of operation: \n");
    printf("* Capture packets at a fixed connection sampling rate (-r).\n");
    printf("* Use a sliding connection sampling rate to try to capture at the optimal rate for the box (read: 0%% packet loss).\n");
    printf("In either case, the program runs for a fixed amount of time (-t)\n");
}

void sigint_handler(int s)
{
    printf("Caught SIGINT.  Shutting down ...\n");
    _done = true;
}

int main(int argc, char *argv[])
{
    // overhead ...
    double         current_rate = 100.0;
    double         target_rate = 100.0;
    char           errbuf[PCAP_ERRBUF_SIZE];
    const uint8_t* pkt_buf;
    // spend some time sleeping to make it seem like we're doing something interesting with the traffic.
    // used to test the application's dynamic sampling, but no real practical use otherwise.
    uint64_t       synthetic_processing_latency = 0;
    int            res_next_ex = 0;    
    pcap_pkthdr*   pkt_header = NULL;

    // defaults ...
    unsigned int   seed = time(0);
    char*          capture_dev = NULL;
    char*          trace_out = NULL;
    // capture for 60 seconds by default.
    double         execution_time = 60.0;
    // adjust connection sampling once / second (ms).
    unsigned int   drop_timeout = 1000;
    int            expected_connections = BLOOM_NUM_ELEMENTS;
    double         target_probability = BLOOM_TARGET_PROB;    
    bool           dynamic_sampling = true;

    opterr = 0;
    int c = 0; 
    while ((c = getopt (argc, argv, "d:hi:r:s:t:w:E:P:S:")) != -1)
    {

        switch (c)
            {
            case 'd':
                drop_timeout = atoi(optarg);
                break;
            case 'h':
                usage();
                return 0;
            case 'i':
                capture_dev = strdup(optarg);
                break;
            case 'r':
                target_rate = atof(optarg);
                dynamic_sampling = false;
                break;
            case 's':
                seed = atoi(optarg);
                break;
            case 't':
                execution_time = atoi(optarg);
                break;
            case 'w':
                trace_out = strdup(optarg);
                break;
            case 'E':
                expected_connections = atoi(optarg);
                break;
            case 'P':
                target_probability = atof(optarg);
                break;
            case 'S':
                synthetic_processing_latency = atoi(optarg);
                break;
            case '?':
                fprintf (stderr, "Invalid option: either an argument is missing or this parameter is not known: `-%c'.\n", optopt);
                return 1;
            default:
		fprintf (stderr, "Unhandled option (%d).  Aborting ...\n", c);
                abort();
            }
    }

    if(NULL == capture_dev) {
        fprintf(stderr, "Capture device (-i) is required.\n");
        return 3;
    }

    // when the program started ...
    double         start_ts = 0.0;
    // used to track when drops were last reset ...
    double         last_drop_ts = 0.0;
    uint64_t       last_drop_count = 0;
    uint64_t       last_packet_count = 0;    

    uint64_t       packets_discarded = 0;
    uint64_t       new_connection_count = 0;
    uint64_t       last_connection_count = 0;

    // Use a bloom filter to keep a rough idea of connections we've seen ...
    // We'll use this as a rough guideline for adjusting our connection drop rate.
    struct   bloom filter;
    printf("Initializing filter...\n");
    bloom_init(&filter, expected_connections, target_probability);
    
    _seed = seed;
    // Initialize packet capture ...
    pcap_t *device_handle;
    printf("Starting packet capture...\n");
    device_handle = pcap_open_live(capture_dev, PKTBUF_SZ, 1, 1000, errbuf);
    if(NULL == device_handle) {
        fprintf(stderr, "[FATAL] Couldn't open device %s: %s\n", capture_dev, errbuf);
        return(2);
    }
   
    if (pcap_datalink(device_handle) != DLT_EN10MB) {
        fprintf(stderr, "[FATAL] Capture device %s uses unknown link type: %d\n", capture_dev, pcap_datalink(device_handle));
        return(2);
    }
    
    pcap_dumper_t *dump_file = NULL;
    if (trace_out) {
        dump_file = pcap_dump_open(device_handle, trace_out);
        if(!dump_file) {
            fprintf(stderr, "[FATAL] Could not open trace file: %s\n", trace_out);
            return(4);
        }
    }

    struct sigaction sig_handler;

    sig_handler.sa_handler = sigint_handler;
    sigemptyset(&sig_handler.sa_mask);
    sig_handler.sa_flags = 0;

    sigaction(SIGINT, &sig_handler, NULL);

    printf("Off we go.\n");
    while(!_done && (res_next_ex = pcap_next_ex( device_handle, &pkt_header, &pkt_buf )) >= 0) {
        if(0 == res_next_ex) {
            continue;
        }
        
        double network_ts = pkt_header->ts.tv_sec + pkt_header->ts.tv_usec / 1000000.0;
        if(last_drop_ts < 0.001) {
            last_drop_ts = network_ts;
            start_ts = network_ts;
        }
        
        if(start_ts > 0.001 && (network_ts - start_ts) > execution_time) {
            _done = true;
        }
        
        if(dynamic_sampling && network_ts >= last_drop_ts + (drop_timeout / 1000.0) ) {
            last_drop_ts = network_ts;
            pcap_stat stats;
            pcap_stats(device_handle, &stats);
            double pkts_per_conn = stats.ps_recv / ((double)new_connection_count);
            uint64_t drop_count = stats.ps_drop - last_drop_count;
            uint64_t connection_count = new_connection_count - last_connection_count;
            uint64_t connection_count_actual = connection_count;  // needed in the event we adjust connection_count because it's 0 ...
            if(connection_count == 0) {
                connection_count = 1;
            }
            last_drop_count = stats.ps_drop;
            last_connection_count = new_connection_count;
            if(drop_count > 0) {
                // what percentage of new connections have been dropped, relatively speaking?
                // estimated as the number of packets dropped / avg pkts per connection (to give us an estimate of the number of connections dropped)
                // divided by the total number of new connections seen.
                // adjusted by the percentage of connections that
                double drop_rate = ((drop_count / pkts_per_conn) / connection_count);
                current_rate = 100.0 * (1.0 - drop_rate);
                if(current_rate < 0) {
                    current_rate = 0.0;
                }
                if(current_rate > 100) {
                    current_rate = 100.0;
                }
                printf("[%0.6f] (+%llu dropped, %u total, +%llu connections)\n", network_ts, drop_count, stats.ps_recv, connection_count_actual);
            }
            else {
                current_rate = 100.0;
            }
            target_rate = 100 * (1.0 - ((stats.ps_drop / (double)pkts_per_conn) / new_connection_count));
            printf("[%0.6f] Rate: %0.4f / %0.4f (%llu connections [+%llu], %u received)\n", network_ts, current_rate, target_rate, new_connection_count, connection_count_actual, stats.ps_recv);
        }
        
        if(!is_usable_packet(pkt_header, pkt_buf)) {
            continue;
        }
        
        unsigned int connection_hash = build_connection_hash(pkt_header, pkt_buf);

        if(connection_hash % 10000 > target_rate * 100) {
            ++packets_discarded;
            continue;
        }
        
        if(trace_out) {
            pcap_dump((u_char *)dump_file, pkt_header, pkt_buf);
        }
        if(!dynamic_sampling) {
            continue;
        }
        
        if(!bloom_check(&filter, &connection_hash, sizeof(connection_hash))) {
            ++new_connection_count;
            bloom_add(&filter, &connection_hash, sizeof(connection_hash));
        }
        
        // we need to pretend to do something with the packet (beyond just capturing it).
        // used to more easily generate a situation where we're dropping packets ...
        if(synthetic_processing_latency > 0) {
            usleep(synthetic_processing_latency);
        }
    }
    
    if(trace_out) {
        pcap_dump_close(dump_file);
    }
    free(trace_out);
    free(capture_dev);
    bloom_free(&filter);
}

struct connection_info_v4 {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  type;
};

struct connection_info_v6 {
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  type;
};

bool is_usable_packet(pcap_pkthdr *pkt_header, const uint8_t *pkt_buf) {
    uint32_t pkt_len = pkt_header->len;
    uint16_t datatype = htons(*((uint16_t *)(pkt_buf + 12)));
    uint16_t etherlen = 14 + (datatype == 0x8100 ? 4 : 0);
    // 802.1Q, so jump another 4 ahead to pull the actual type ...
    if(datatype == 0x8100) {
        datatype = htons(*((uint16_t *)(pkt_buf + 16)));
    }
    // IPv4 or IPv6
    if(datatype != 0x86dd && datatype != 0x0800) {
        return false;
    }
    const uint8_t *ip_pkt = pkt_buf + etherlen;
    uint8_t ip_version = (*(ip_pkt) & 0xf0) >> 4;

    if(4 != ip_version && 6 != ip_version) {
        return false;
    }

    if(4 == ip_version) {
        uint8_t ip_proto = ip_pkt[9];
        if(ip_proto != IP_PROTO_TCP && ip_proto != IP_PROTO_UDP && ip_proto != IP_PROTO_ICMP) {
            return false;
        }
    }
    else {
        uint8_t next_header = ip_pkt[6];
        if(next_header != IP_PROTO_TCP && next_header != IP_PROTO_UDP && next_header != IP_PROTO_ICMP) {
            return false;
        }
    }

    return true;
}

unsigned int build_connection_hash(pcap_pkthdr *pkt_header, const uint8_t *pkt_buf) {
    uint32_t pkt_len = pkt_header->len;
    uint16_t datatype = htons(*((uint16_t *)(pkt_buf + 12)));
    // 801.Q
    uint16_t etherlen = 14 + (datatype == 0x8100 ? 4 : 0);
    if(datatype == 0x8100) { 
        datatype = htons(*((uint16_t *)(pkt_buf + 16)));
    }
    const uint8_t *ip_pkt = pkt_buf + etherlen;
    uint8_t ip_version = (*(ip_pkt) & 0xf0) >> 4;

    // IPv4 5-tuple ...
    if(4 == ip_version) {
        connection_info_v4 info;
        uint8_t ip_len = (*(ip_pkt) & 0x0f) * 4;
        uint8_t ip_proto = ip_pkt[9];
        info.src_addr = *((uint32_t *)(ip_pkt + 12)); 
        info.dst_addr = *((uint32_t *)(ip_pkt + 16));
        if(ip_proto == IP_PROTO_TCP || ip_proto == IP_PROTO_UDP) {
            const uint8_t *proto_pkt = ip_pkt + ip_len;
            info.src_port = htons(*((uint16_t *)(proto_pkt)));
            info.dst_port = htons(*((uint16_t *)(proto_pkt + 2)));
        }
        else {
            // more of a connection 3-tuple, really, when dealing with other protocols ...
            info.src_port = 0;
            info.dst_port = 0;
        }
        info.type = ip_proto;
        return murmurhash2(&info, sizeof(info), _seed);
    }
    else if(6 == ip_version) {
        connection_info_v6 info;
        uint8_t next_header = ip_pkt[6];
        const uint8_t *last_pkt = ip_pkt;
        for(int i = 0; i < 16; ++i) {
            info.src_addr[i] = ip_pkt[8 + i];
            info.dst_addr[i] = ip_pkt[24 + i];
        }
        if(next_header == IP_PROTO_TCP || next_header == IP_PROTO_UDP) {
            const uint8_t *proto_pkt = ip_pkt + 40;
            info.src_port = htons(*((uint16_t *)(proto_pkt)));
            info.dst_port = htons(*((uint16_t *)(proto_pkt + 2)));
            info.type = next_header;
            return murmurhash2(&info, sizeof(info), _seed);
        }
        else {
            return 0;
        }
        return 0;
    }
    else {
        printf("[%f] Unknown IP type: %d\n", (pkt_header->ts.tv_sec + (pkt_header->ts.tv_usec / 1000000.0)), ip_version);
        return 0;
    }

}

