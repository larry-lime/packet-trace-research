headers = A49.h A50.h AEnt.h ARP.h ASubnet.h Anon.h \
	ConstChecker.h DataProcessor.h DataProcessor-inl.h \
	EtherAddr.h Ethernet.h \
	FieldType.h Hash.h ICMP.h IP.h IPAddr.h IPAnon.h Packet.h \
	Prefix.h PrefixTree.h RPerm.h Scanner.h Special.h \
	TCP.h TCPMkPub.h Topology.h UDP.h \
        common.h md5.h case.macros field.macros

bin_PROGRAMS = tcpmkpub tcpmkpub_keygen

tcpmkpub_SOURCES = Main.cc TCPMkPub.cc \
        DataProcessor.cc Packet.cc \
	Topology.cc Scanner.cc Special.cc \
        Ethernet.cc EtherAddr.cc \
        ARP.cc IP.cc IPAddr.cc TCP.cc UDP.cc ICMP.cc \
	Prefix.cc RPerm.cc \
    	A50.cc A49.cc AEnt.cc ASubnet.cc \
	md5.c \
	${headers}

tcpmkpub_CPPFLAGS = -Wall

tcpmkpub_LDADD = -lpcap

tcpmkpub_keygen_SOURCES = tcpmkpub_keygen.cc md5.c
