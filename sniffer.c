#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define TEMP_FILE "packet_data.txt"

// Mutex for thread safety when writing to file
pthread_mutex_t lock;

struct packet_data {
    char src_ip[16];
    char dst_ip[16];
    int protocol;
    int src_port;
    int dst_port;
    int syn_flag;
    int ack_flag;
};

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_hdr = (struct ip *)(packet + 14); // Offset for Ethernet header
    struct packet_data pkt;
    strncpy(pkt.src_ip, inet_ntoa(ip_hdr->ip_src), 16);
    strncpy(pkt.dst_ip, inet_ntoa(ip_hdr->ip_dst), 16);
    pkt.protocol = ip_hdr->ip_p;
    pkt.syn_flag = 0;
    pkt.ack_flag = 0;

    if (pkt.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr->ip_hl * 4);
        pkt.src_port = ntohs(tcp_hdr->th_sport);
        pkt.dst_port = ntohs(tcp_hdr->th_dport);
        pkt.syn_flag = tcp_hdr->th_flags & TH_SYN ? 1 : 0;
        pkt.ack_flag = tcp_hdr->th_flags & TH_ACK ? 1 : 0;
    } else {
        pkt.src_port = pkt.dst_port = 0;
    }

    // Write data to a temporary text file
    pthread_mutex_lock(&lock);
    FILE *tempfile = fopen(TEMP_FILE, "a");
    if (tempfile != NULL) {
        fprintf(tempfile, "%s %s %d %d %d %d %d\n",
                pkt.src_ip, pkt.dst_ip, pkt.protocol, pkt.src_port, pkt.dst_port, pkt.syn_flag, pkt.ack_flag);
        fclose(tempfile);
    }
    pthread_mutex_unlock(&lock);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    pthread_mutex_init(&lock, NULL);
    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Clear the temp file before starting capture
    FILE *tempfile = fopen(TEMP_FILE, "w");
    if (tempfile != NULL) fclose(tempfile);

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    pthread_mutex_destroy(&lock);
    return 0;
}
