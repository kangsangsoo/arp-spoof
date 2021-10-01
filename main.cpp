#include "send-arp.h"

int main(int argc, char* argv[]) {

	auto startTime = std::chrono::system_clock::now();

	while (1) {
		auto endTime = std::chrono::system_clock::now();
		for(int i = 0; i < 1<<25; i++);
		auto diff = std::chrono::duration_cast<std::chrono::seconds>(endTime-startTime);
		cout << diff.count() << endl;
	}

	return 0;
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
		if(resolveMac(handle, ARPtable, me, sender) == FAIL) continue;
		if(resolveMac(handle, ARPtable, me, target) == FAIL) continue;

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

	pcap_close(handle);
	return 0;
}
