#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<pcap/pcap.h>
#define LIBNET_LIL_ENDIAN 1
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARPHRD_ETHER 1
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

struct libnet_ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};
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
struct arp_hdr {
  u_int16_t htype;
  u_int16_t ptype;
  u_int8_t hlen;
  u_int8_t plen;
  u_int16_t opcode;
  u_int8_t sender_mac[6];
  u_int8_t sender_ip[4];
  u_int8_t target_mac[6];
  u_int8_t target_ip[4];
};
struct libnet_ether_addr
{
    u_int8_t  ether_addr_octet[6];        /* Ethernet address */
};
struct MAC_IP_Address
{
	struct in_addr idr;
	struct libnet_ether_addr mdr;
};
struct MAC_IP_Address getDevAddr()
{
	static struct MAC_IP_Address miAddr;
	FILE* fp;
	char *dev;
    char cmd[256] = {0x0}, errbuf[PCAP_ERRBUF_SIZE];
	char buf_ip[20] = {0x0};
	char buf_mac[20] = {0x0};
	dev = pcap_lookupdev(errbuf);
	sprintf(cmd,"ifconfig | grep '%s' | awk '{print $5}'", dev);
	fp = popen(cmd, "r");
	fgets(buf_mac, sizeof(buf_mac), fp);
	pclose(fp);
	ether_aton_r(buf_mac, &miAddr.mdr);
	sprintf(cmd,"ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'", dev);
	fp = popen(cmd, "r");
	fgets(buf_ip, sizeof(buf_ip), fp);
	pclose(fp);
	inet_aton(buf_ip, &miAddr.idr);
	return miAddr;
}
struct in_addr getGatewayIP()
{
	static struct in_addr gatewayIP;
	FILE* fp;
	char *dev;
    char cmd[256] = {0x0}, errbuf[PCAP_ERRBUF_SIZE];
	char buf_ip[20] = {0x0};
	dev = pcap_lookupdev(errbuf);
	sprintf(cmd,"route -n | grep '%s'  | grep 'UG' | awk '{print $2}'", dev);
	fp = popen(cmd, "r");
	fgets(buf_ip, sizeof(buf_ip), fp);
	pclose(fp);
	inet_aton(buf_ip, &gatewayIP);
    return gatewayIP;
}

int main(int argc, char *argv[])
{
	struct libnet_ether_addr mMac;
	struct libnet_ether_addr vMac;
	struct in_addr victimIP;
	struct arp_hdr *mArphdr;
	struct libnet_ethernet_hdr *mEthdr;
	struct pcap_pkthdr pkthdr;
	const u_char* userData;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *DevName;
    pcap_t* ID;
	char errbuf[PCAP_ERRBUF_SIZE];
    DevName = pcap_lookupdev(errbuf);
	if(DevName==0)
	{
		printf("Error : [%s]\n", errbuf);
		return 1;
	}
	printf("Network Device Name : [%s]\n", DevName);
	ID = pcap_open_live(DevName, 1024, 0, 1000, errbuf);
	int inet_aton(argv[1], &vMac);
	struct pcap_pkthdr *rec_pkthdr;
	const u_char *rec_packet;
	u_char Packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct arp_hdr)];
	make_arp_packet(Packet, getDevAddr().idr, getDevAddr().mdr, victimIP, mMac, ARP_OP_REQUEST);

	//..........
}

void make_arp_packet(u_char *packet, const struct in_addr sendIP, const struct libnet_ether_addr sendMAC, const struct in_addr targIP, const struct libnet_ether_addr targMAC, uint16_t arp_op)
{
	struct arp_hdr arphdr;
	struct libnet_ethernet_hdr ethdr;
	ethdr.ether_type = htons(ETHERTYPE_ARP);
	memcpy(ethdr.ether_dhost, &targMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(ethdr.ether_shost, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);
	arphdr.htype = htons(ARPHRD_ETHER);
	arphdr.ptype = htons(ETHERTYPE_IP);
	arphdr.hlen = ETHER_ADDR_LEN;
	arphdr.plen = sizeof(4);
	arphdr.opcode = htons(arp_op);
	memcpy(&arphdr.sender_mac, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&arphdr.sender_ip, &sendIP.S_un, sizeof(4));
	memcpy(&arphdr.target_mac, &targMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&arphdr.target_ip, &targIP.S_un, sizeof(4));
	memcpy(packet, &ethdr, sizeof(struct libnet_ethernet_hdr));
	memcpy(packet+sizeof(struct libnet_ethernet_hdr), &arphdr, sizeof(struct arp_hdr));
	return;
}