## Process this file with automake to create Makefile.in
CLEANFILES = *~

bin_PROGRAMS = tcpurify
tcpurify_SOURCES = main.c capture.c dump.c timeval.c encodings.c \
                   timeval.h tcpurify.h \
                   encode_none.c encode_none.h \
                   encode_nullify.c encode_nullify.h \
                   encode_table.c encode_table.h
tcpurify_LDADD = @PCAP_LDFLAGS@
INCLUDES := $(INCLUDES) @PCAP_INCLUDES@

EXTRA_DIST = $(ac_aux_dir)/config.guess $(ac_aux_dir)/config.sub \
             $(ac_aux_dir)/install-sh $(ac_aux_dir)/missing \
             $(ac_aux_dir)/mkinstalldirs
