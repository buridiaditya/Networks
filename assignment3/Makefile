binaries: tcp udp 
	@echo "Binaries generated in their respective folders."
tcp: tcpserver tcpclient

udp: udpserver udpclient

tcpserver: 
	@icc server/tcpserver.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o server/tcpserver -lssl -lcrypto -lm
tcpclient:
	@icc client/tcpclient.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o client/tcpclient -lssl -lcrypto
udpserver:
	@icc server/udpserver.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o server/udpserver -lssl -lcrypto -lm
udpclient:
	@icc client/udpclient.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o client/udpclient -lssl -lcrypto -lm
