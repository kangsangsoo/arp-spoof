#include "send-arp.h"

int main(int argc, char* argv[]) {

	// 입력 인자 개수가 4개 이상이어야 하며 짝수여야함.
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	
	
	// unordered_map vs map
	std::map<Ip, Mac> ARPtable;
	getMyInfo(dev, ARPtable);
	Ip sender, target, me = getMyIp(dev);

	int now = 2;

	// 전처리를 하자 
	// resolve를 미리 다 해놓자
	std::vector <pair<Ip, Ip>> IpTable; // {sender, target}
	while(now < argc) {
		initArg(&argv[now], sender, target);
		IpTable.push_back({sender, target});
		// sender랑 target Mac 찾기
		if(resolveMac(handle, ARPtable, me, sender) == FAIL);
		if(resolveMac(handle, ARPtable, me, target) == FAIL);

		//printTable(ARPtable);

		// 감염 시키는건데 

		/*
		// me, sender, target의 Ip 구조체를 넘겨주고 맥주소는 table에서 알아서 찾도록
		cout << "go to trehad" << endl;
		std::thread t(infection, handle, ARPtable, me, sender, target); 
		t.join();
		*/
		now = now + 2;
	}

	for(auto i = ARPtable.begin(); i != ARPtable.end(); i++) {
		cout << string(i->first) << ' ' << string(i->second) << endl;
	}

	// infection 실행
	cout << "infection start" << endl;
	for(int i = 0; i < IpTable.size(); i++) {
		std::thread t(infection, handle, ARPtable, me, IpTable[i].first, IpTable[i].second, 10, 1);
		t.detach();
	}


	// watchPacket으로
	// IP 패킷일 경우 => flow로 
	// ARP 패킷일 경우 => 감염으로 대응해줘야 함
	// 1초당 1번씩 보내고 있을 때 그닥 걱정은 안됨
	// 더 큰 주기로 보낸다 했을 때 ARP Table 복구를 염두해야함.
	 



	
	// 10초 대기
	auto startTime = std::chrono::system_clock::now();
	while (1) {
		auto endTime = std::chrono::system_clock::now();
		auto diff = std::chrono::duration_cast<std::chrono::seconds>(endTime-startTime);
		if(diff.count() > 10) {
			break;
		}
	}




	// infection말고 recover를 실행
	// void infection(pcap_t* handle, map<Ip, Mac> table, Ip me, Ip sender, Ip target, Ip times, Ip sec) 
	// void recover(pcap_t* handle, map<Ip, Mac>& table, Ip& sender, Ip& target) {
	findFlag = 1;
	cout << "infection end" << endl;
	
	// 2초 대기
	startTime = std::chrono::system_clock::now();
	while (1) {
		auto endTime = std::chrono::system_clock::now();
		auto diff = std::chrono::duration_cast<std::chrono::seconds>(endTime-startTime);
		if(diff.count() > 2) {
			break;
		}
	}

	cout << "recover start" << endl;
	findFlag = 0;
	std::thread t_[10];

	for(int i = 0; i < IpTable.size(); i++) {
		t_[i] = std::thread(recover, handle, ARPtable, IpTable[i].first, IpTable[i].second);
	}
	for(int i = 0; i < IpTable.size(); i++) {
		t_[i].join();
	}
	cout << "program end" << endl;
	pcap_close(handle);
	return 0;
}
