all: parser.c server.c network.c clients.c
	gcc server.c parser.c network.c clients.c -o server
