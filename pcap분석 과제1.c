#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<pcap/pcap.h>
#include<WinSock2.h>
#pragma comment (lib, "ws2_32")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")
#define LIBNET_LIL_ENDIAN 1
void callback(u_char *useless, const struct pcap_pkthdr *h, const u_char *p);

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800

struct libnet_ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};
typedef struct libnet_ethernet_hdr ethhd;

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
	
	u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
	u_int8_t ip_tos;       /* type of service */
    short ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    short ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    uint8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
};

void MacADDR(unsigned char *mac)
{
	int i;
	for(i=0; i<ETHER_ADDR_LEN; i++)
	{
		printf("%02x:", mac[i]);
	}
}

void Ethernet(const u_char *buf)
{
	ethhd *eth= (ethhd *)buf;
	printf("< Ethernet Header >\n");
	printf("Dest mac:0x");
    MacADDR(eth->ether_dhost);
	printf("\n Src mac:0x");
	MacADDR(eth->ether_shost);
	printf("\ntype:%#x ==> ", ntohs(eth->ether_type));
}

void callback(u_char *useless, const struct pcap_pkthdr *h, const u_char *p)
{
    struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *iph;
	struct libnet_tcp_hdr *tcph;
    unsigned short ether_type;    
    int i =0;
    int length=h->len;
    eth = (struct libnet_ethernet_hdr *)p;
	Ethernet(p);
    p += sizeof(ethhd);
    ether_type = ntohs(eth->ether_type);
    if (ether_type == ETHERTYPE_IP)
    {
        iph = (struct libnet_ipv4_hdr * )p;
        printf("< IP packet >\n");
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));
		printf("version: %d\n", iph->ip_v);
		printf("Protocol ID : %d\n", iph->ip_p);
        if (iph->ip_p == IPPROTO_TCP)
        { 
            tcph = (struct libnet_tcp_hdr *)(p + iph->ip_hl * 4);
            printf("Src Port : %d\n" , ntohs(tcph->th_sport));
            printf("Dst Port : %d\n" , ntohs(tcph->th_dport));
        }
        while(length--)
        {
            printf("%02x", *(p++)); 
            if ((++i % 16) == 0) 
                printf("\n");
        }
    }
    else
    {
        printf("< None IP packet >\n");
    }
    printf("\n\n");
}

int main()
{
	struct pcap_pkthdr pkthdr;
	const u_char* userData;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *DevName;
    pcap_t* ID;
	DevName = pcap_lookupdev(errbuf);
	if(DevName==0)
	{
		printf("Error : [%s]\n", errbuf);
		return 100;
	}
	printf("Network Device Name : [%s]\n", DevName);
	ID = pcap_open_live(DevName, 1024, 1, 1000, errbuf);
	if(ID==0)
    {
		printf("Error : [%s]\n", errbuf);
		return 101;
    }
    userData = pcap_next(ID, &pkthdr);
	printf("doing...\n\n");
	pcap_loop(ID, -1, callback, NULL);
	pcap_close(ID); 
	return 1;
}