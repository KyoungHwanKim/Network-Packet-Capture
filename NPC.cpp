#include <stdio.h>
#include <pcap.h> // PCAP 라이브러리
#include <arpa/inet.h> // 함수
#include <netinet/in.h> // 구조체

#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC
    u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC
    u_short ether_type;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

struct sniff_ip {
        u_char ip_vhl;
        u_char ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char ip_ttl;
        u_char ip_p; // IP 프로토콜 유형
        u_short ip_sum;
        struct in_addr ip_src; // 출발지 IP
        struct in_addr ip_dst; // 목적지 IP
};

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport; // 출발지 TCP 주소
        u_short th_dport; // 목적지 TCP 주소
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};

#define SIZE_ETHERNET 14

struct sniff_ethernet *ethernet; // Ethernet Header
struct sniff_ip *ip; // IP Header
struct sniff_tcp *tcp; // TCP Header

u_int size_ip, size_tcp;

pcap_t *handle; // 핸들러
char *dev; // 자신의 네트워크 장비
char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메세지 담는 버퍼
struct bpf_program fp; // 필터 구조체
char *filter_exp; // 필터 표현식
bpf_u_int32 mask; // 서브넷 마스크
bpf_u_int32 net; // IP 주소
struct pcap_pkthdr *header; //패킷 관련 정보
const u_char *packet; // 실제 패킷
struct in_addr addr; // 주소 정보

int main(void) {
    dev = pcap_lookupdev(errbuf); // 네트워크 장비 체크

    if (dev == NULL) {
        printf("장치를 자동으로 찾을 수 없음.\n");
        return 0;
    }
    
    printf("장치 이름 : %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("장치의 주소를 찾을 수 없음.\n");
        return 0;
    }
    
    addr.s_addr = net;
    printf("나의 IP 주소 : %s\n", inet_ntoa(addr));
    addr.s_addr = mask;
    printf("나의 서브넷 마스크 %s\n", inet_ntoa(addr));

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("장치를 열 수 없음.\n");
        return 0;
    }
    
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("필터를 적용할 수 없음.\n");
        return 0;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("필터를 세팅할 수 없음.\n");
        return 0;
    }

    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        printf("------------------------------------------------------\n");
        int i;
        ethernet = (struct sniff_ethernet*)(packet);
        printf("MAC 출발지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_shost[i]);
        }
        printf("\nMAC 목적지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_dhost[i]);
        }
        printf("\nMAC 목적지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_dhost[i]);
        }
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        printf("\nIP 출발지 주소: %s\n", inet_ntoa(ip->ip_src));
        printf("IP 목적지 주소: %s\n", inet_ntoa(ip->ip_dst));
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        printf("출발지 포트: %d\n", ntohs(tcp->th_sport));
        printf("목적지 포트: %d\n", ntohs(tcp->th_dport));
        printf("\n------------------------------------------------------\n");
    }

    return 0;
}
