//
// Created by fireflyc on 2016/12/26.
//
#include <stdlib.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>

#define TRUE (1==1)
#define FALSE (1==0)
#define IP2UINT32(up) *((uint32_t *)&up)

typedef struct tcp_packet {
    uint32_t seq;
    uint32_t ack;
    uint8_t control;

    uint16_t dport;
    uint16_t sport;
    in_addr_t dst_addr;
    in_addr_t src_addr;
} tcp_packet_t;

typedef struct arphdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
} arphdr_t;

typedef struct client_context {
    const char *dev;
    pcap_t *pcap;

    uint16_t request_port;
    struct in_addr request_ip;

    struct in_addr self;
} client_context_t;

int send_tcp(tcp_packet_t *tcp_pkt, client_context_t *context, char *errbuf) {
    libnet_t *libnet = libnet_init(LIBNET_RAW4, context->dev, errbuf);//raw socket
    if (libnet == NULL) {
        snprintf(errbuf, BUFSIZ, "open libnet error %s", errbuf);
        return FALSE;
    }
    libnet_ptag_t t = libnet_build_tcp(
            tcp_pkt->sport, // source port
            tcp_pkt->dport, // dest port
            tcp_pkt->seq, // sequence number
            tcp_pkt->ack, // ack number
            tcp_pkt->control, // flags //ACK确认用户发送的请求数据包 push立即发送 FIN只在最后一条数据设置
            255, // window size
            0, // checksum
            0, // urg ptr //
            (uint16_t) LIBNET_TCP_H, // total length of the TCP packet
            NULL, // response
            0, // response_length
            libnet, // libnet_t pointer
            0 // ptag
    );
    if (t == -1) {
        snprintf(errbuf, BUFSIZ, "Can't build TCP header: %s", libnet_geterror(libnet));
        goto bad;
    }
    t = libnet_build_ipv4(
            (uint16_t) (LIBNET_IPV4_H + LIBNET_TCP_H), // length
            // TOS bits 最小延时、最大吞吐量、最高可靠性 最小费用 这个字段一般会被设备忽略。
            0, //不设置
            (uint16_t) libnet_get_prand(LIBNET_PRu16), // IPID 16位随机数
            IP_DF, // fragmentation 不分片
            64, // TTL 一般设置为64达到64就可以死了延时太高了
            IPPROTO_TCP, // protocol, 表示使用TCP协议
            0, // checksum
            tcp_pkt->src_addr, // source address
            tcp_pkt->dst_addr, // dest address
            NULL, // response
            0, // response length //
            libnet, // libnet_t pointer
            0
    );
    if (t == -1) {
        snprintf(errbuf, BUFSIZ, " Can't build IP header: %s", libnet_geterror(libnet));
        goto bad;
    }
    int write_size = libnet_write(libnet);
    if (write_size == -1) {
        snprintf(errbuf, BUFSIZ, "Writer error %s", libnet_geterror(libnet));
        goto bad;
    }
    libnet_destroy(libnet);
    return TRUE;
    bad:
    libnet_destroy(libnet);
    return FALSE;
}


int send_arp(struct libnet_ethernet_hdr *eth_hdr, arphdr_t *arp_hdr, client_context_t *context, char *errbuf) {
    libnet_t *net = libnet_init(LIBNET_LINK, context->dev, errbuf);
    struct libnet_ether_addr *mac_addr = libnet_get_hwaddr(net);
    libnet_ptag_t t = libnet_autobuild_arp(
            ARPOP_REPLY,                           /* operation type */
            (const uint8_t *) mac_addr,                              /* sender hardware addr */
            (uint8_t *) &arp_hdr->tpa,       /* sender protocol addr */
            eth_hdr->ether_shost,                  /* target hardware addr */
            (uint8_t *) &arp_hdr->spa,       /* target protocol addr */
            net);                                     /* libnet id */

    if (t == -1) {
        snprintf(errbuf, BUFSIZ, "Can't build ARP header: %s", libnet_geterror(net));
        goto bad;
    }
    t = libnet_build_ethernet(
            arp_hdr->sha,                           /* ethernet destination */
            (const uint8_t *) mac_addr,
            ETHERTYPE_ARP,                          /* protocol type */
            NULL,
            0,
            net, /* libnet handle */
            0);
    if (t == -1) {
        snprintf(errbuf, BUFSIZ, "Can't build ethernet header: %s", libnet_geterror(net));
        goto bad;
    }
    int write_size = libnet_write(net);
    if (write_size == -1) {
        snprintf(errbuf, BUFSIZ, "Writer error %s", libnet_geterror(net));
        goto bad;
    }
    libnet_destroy(net);
    return TRUE;

    bad:
    libnet_destroy(net);
    return FALSE;
}

void on_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    client_context_t *context = (client_context_t *) arg;
    char errbuf[BUFSIZ];

    struct libnet_ethernet_hdr *ether_hdr = (struct libnet_ethernet_hdr *) packet;
    if (ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP) {
        arphdr_t *arp_hdr = (arphdr_t *) (packet + LIBNET_ETH_H);
        if (ntohs(arp_hdr->oper) == ARPOP_REQUEST &&
            (context->self.s_addr == IP2UINT32(arp_hdr->spa) || context->self.s_addr == IP2UINT32(arp_hdr->tpa))) {
            printf("received arp query\n");
            //收到ARP
            memset(errbuf, 0, BUFSIZ);
            if (!send_arp(ether_hdr, arp_hdr, context, errbuf)) {
                printf("send response error %s\n", errbuf);
            }
        }
        return;
    }

    struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
    uint ip_size = (uint) ip_hdr->ip_hl * 4;
    if (ip_size < 20) {
        return;
    }
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return;
    }
    //确定是TCP数据包
    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + ip_size);
    uint tcp_size = (uint) (tcp_hdr->th_off * 4);
    if (tcp_size < 20) {
        return;
    }
    uint payload_size = (uint) (ntohs(ip_hdr->ip_len) - (ip_size + tcp_size));
    if (payload_size == 0) {
        if (tcp_hdr->th_flags == (TH_ACK | TH_SYN) && ntohs(tcp_hdr->th_sport) == context->request_port) {
            //握手数据包
            tcp_packet_t pkt;
            pkt.control = TH_ACK;
            pkt.seq = ntohl(tcp_hdr->th_ack);
            pkt.ack = ntohl(tcp_hdr->th_seq) + 1;
            pkt.src_addr = ip_hdr->ip_dst.s_addr;
            pkt.dst_addr = ip_hdr->ip_src.s_addr;
            pkt.sport = ntohs(tcp_hdr->th_dport);
            pkt.dport = ntohs(tcp_hdr->th_sport);
            if (!send_tcp(&pkt, context, errbuf)) {
                printf("ack error %s\n", errbuf);
            }
            return;
        }
    }
}

int tcp_syn(uint16_t local_port, client_context_t *context) {
    char errbuf[BUFSIZ];
    tcp_packet_t pkt;
    pkt.seq = libnet_get_prand(LIBNET_PRu32); //随机seq
    pkt.control = TH_SYN; //SYN
    pkt.src_addr = context->self.s_addr; //"我"的IP
    pkt.dst_addr = context->request_ip.s_addr;//目标IP
    pkt.sport = local_port; //本机端口
    pkt.dport = context->request_port;//目标端口
    if (!send_tcp(&pkt, context, errbuf)) {
        printf("sync error %s\n", errbuf);
        return FALSE;
    }
    return TRUE;
}


pcap_t *init_pcap(const char *dev, const char *filter_exp, char *errbuf) {
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
        snprintf(errbuf, BUFSIZ, "lookup %s failed", dev);
        return NULL;
    }
    pcap_t *pcap = pcap_open_live(dev, 1500, 1, 1, errbuf);
    if (pcap == NULL) {
        return NULL;
    }
    if (filter_exp != NULL) {
        struct bpf_program fp;
        if (pcap_compile(pcap, &fp, filter_exp, 1, netp) == -1) {
            snprintf(errbuf, BUFSIZ, "Compile filter expression failed %s cause: %s", filter_exp,
                     pcap_geterr(pcap));
            pcap_close(pcap);
            return NULL;
        }
        if (pcap_setfilter(pcap, &fp) == -1) {
            snprintf(errbuf, BUFSIZ, "Install filter failed %s", pcap_geterr(pcap));
            pcap_close(pcap);
            return NULL;
        }
    }
    return pcap;
}

/**
 * 发送TCP SYN(1-65535端口)，在on_packet中处理三次握手的第二个数据包和ARP数据包
 * */
void *fun(void *context) {
    for (uint16_t i = 1; i < 65535; i++) {
        tcp_syn(i, context);
        printf("send in port %d\n", i);
    }
    return 0;
}

client_context_t *context;

static void termination(int signum) {
    if (context == NULL) {
        return;
    }
    if (context->pcap != NULL) {
        pcap_close(context->pcap);
        context->pcap = NULL;
    }
    free(context);
}

int main(int argc, char **argv) {
    char errbuf[BUFSIZ];
    if (argc != 5) {
        printf("usage tcp-client <dev> <myip> <toip> <port>\n example: tcp-client ens33 172.16.46.200 172.16.46.127 8888\n");
        return EXIT_FAILURE;
    }
    const char *dev = argv[1];
    //设置ctrl+c和kill的信号回调，正常释放资源
    signal(SIGINT, termination);
    signal(SIGTERM, termination);
    //context记录了一些乱七八糟的数据
    context = (client_context_t *) malloc(sizeof(client_context_t));
    inet_aton(argv[2], &context->self);//自己的IP地址
    inet_aton(argv[3], &context->request_ip);//目标IP地址
    context->request_port = atoi(argv[4]);//目标端口
    context->dev = dev;//使用那块网卡
    context->pcap = init_pcap(dev, NULL, errbuf);

    if (context->pcap == NULL) {
        printf("init pcap error %s\n", errbuf);
        return EXIT_FAILURE;
    }

    pthread_t thread;
    pthread_create(&thread, NULL, fun, context);//发送数据的线程

    //开始循环监听数据包,这句话代码会阻塞当前线程
    pcap_loop(context->pcap, -1, on_packet, (u_char *) context);

    return EXIT_SUCCESS;
}