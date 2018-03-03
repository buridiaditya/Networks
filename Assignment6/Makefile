binaries: udp 
	@echo "Binaries generated in their respective folders."

udp: udpserver udpclient

udpserver:
	@gcc server/udpserver.c -o server/udpserver -lssl -lcrypto -lm
udpclient:
	@gcc client/udpclient.c -o client/udpclient -lssl -lcrypto -lm
