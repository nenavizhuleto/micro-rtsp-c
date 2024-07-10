#include "../src/rtsp.h"
#include "../src/session.h"
#include "../src/streamer.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "sample.h"

void handle_client(int client) {
	rtsp_streamer_t streamer;
	rtsp_session_t session;

	rtsp_streamer_init(&streamer, 1920, 1080);
	rtsp_session_init(&session, client, &streamer);

	rtsp_streamer_set_uri(&streamer, "localhost:8554", "mjpeg", "1");

	streamer.is_debug = true;
	session.is_debug = true;

	rtsp_streamer_add_session(&streamer, &session);

	for (;;) {
		rtsp_streamer_start(&streamer, 100);
		rtsp_streamer_stream_frame(&streamer, capture_jpg, capture_jpg_len, 100);
	}


}

int main(void) {

	int sockfd;
	int clientfd;

	struct sockaddr_in serv_addr;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	printf("starting RTSP server\n");

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(8554);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	int enable = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable,  sizeof(int)) < 0) {
		printf("failed to reuse addr\n");
		return 0;
	}

	if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0) {
		printf("failed to bind port errno=%d\n", errno);
		return 0;
	}

	if (listen(sockfd, 5) != 0) return 0;

	for (;;) {
		clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
		printf("client connected: client address %s\r\n", inet_ntoa(client_addr.sin_addr));
		if (fork() == 0) {
			handle_client(clientfd);
		}
	}

	close(sockfd);

	return 0;


}
