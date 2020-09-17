ifeq ($(community),)
community := public
endif

all: compile

compile:
	@gcc -c session.c -o session.o -lnetsnmp
	@gcc -c tcpInfo.c -o tcpInfo.o -lnetsnmp
	@gcc -c udpInfo.c -o udpInfo.o -lnetsnmp
	@gcc -DCOMM="\"$(community)\"" session.o udpInfo.o tcpInfo.o main.c -o portScan -lnetsnmp
	@rm session.o udpInfo.o tcpInfo.o

install: compile
	@mv portScan /usr/bin/portScan

clean:
	@rm portScan -f