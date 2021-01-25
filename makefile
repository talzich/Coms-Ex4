
all: sniffer myping

sniffer: sniffer.c
	gcc sniffer.c -o sniffer

myping: myping.c
	gcc myping.c -o myping

.PHONY: clean

clean: 
	rm -rf sniffer myping
