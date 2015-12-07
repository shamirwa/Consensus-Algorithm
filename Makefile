general:	general.cpp general.h message.h
	g++ -o general general.cpp -lcrypto

clean:
	rm -f general
