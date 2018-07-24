#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h> // 상수 IPPROTO_TCP, IPPROTO_UDP 등을 사용하기 위해 선언한 헤더
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h> // 자료형 intN_t, uintN_t를 사용하기 위해 선언한 헤더
#include <arpa/inet.h> // inet.ntoa() 함수를 사용하기 위해 선언한 헤더


void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}


void printSrcDstMac(struct ether_header *etherHeader) {
		printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", etherHeader->ether_shost[0], etherHeader->ether_shost[1], etherHeader->ether_shost[2], etherHeader->ether_shost[3], etherHeader->ether_shost[4], etherHeader->ether_shost[5]);

		printf("Destination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", etherHeader->ether_dhost[0], etherHeader->ether_dhost[1], etherHeader->ether_dhost[2], etherHeader->ether_dhost[3], etherHeader->ether_dhost[4], etherHeader->ether_dhost[5]);
}


int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true) // TCP 프로토콜만 출력
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
    		printf("%u bytes captured\n", header->caplen);

		struct ether_header *etherHeader;
		struct ip *ipHeader;
		struct tcphdr *tcpHeader;

		// 출발지, 목적지 MAC 주소 출력
		etherHeader = (struct ether_header *)packet;
		printSrcDstMac(etherHeader);

		uint16_t etherType = ntohs(etherHeader->ether_type);

		packet += sizeof(struct ether_header);

		if(etherType == ETHERTYPE_IP)
		{
			ipHeader = (struct ip *)packet;

			printf("Source IP Address : %s\n", inet_ntoa(ipHeader->ip_src));
			printf("Destination IP Address : %s\n", inet_ntoa(ipHeader->ip_dst));

			uint8_t ipProtocol = ipHeader->ip_p;
			
			if(ipProtocol == IPPROTO_TCP)
			{
				uint8_t ipHeaderLength = (ipHeader->ip_hl) * 4;

				packet += ipHeaderLength;

				tcpHeader = (struct tcphdr *)packet;

				printf("Source Port : %d\n",ntohs(tcpHeader->th_sport));
				printf("Destination Port : %d\n",ntohs(tcpHeader->th_dport));

				uint16_t ipTotalLength = ntohs(ipHeader->ip_len);

				int dataLength = ipTotalLength - ipHeaderLength - sizeof(struct tcphdr);

				if(dataLength >= 16)
				{
					packet += sizeof(struct tcphdr);
					printf("data : ");
					for(int i = 0; i < 16; i++)
					{
						printf("%02x",packet[i]);
					}
					printf("\n");
				}
				else if(dataLength <16 and dataLength > 0)
				{
					packet += sizeof(struct tcphdr);
					printf("data : ");
					for(int i = 0; i < dataLength; i++)
					{
						printf("%02x",packet[i]);
					}
					printf("\n");
				}
			}
		}
		printf("\n");
	}
	pcap_close(handle);
	return 0;
}
